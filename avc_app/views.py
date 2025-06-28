from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseForbidden, HttpResponse
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from .models import Session, AttendanceRecord, IPBlacklist, Permission, UserProfile
import requests
import json
from django.utils import timezone
import qrcode
from io import BytesIO
import base64
import secrets
from .utils import get_client_ip, check_ip_security, validate_ip_address
from django.db import IntegrityError, transaction
from .forms import PermissionRequestForm, PermissionApprovalForm, SessionForm
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import csv
from datetime import datetime
from django.db.models import Count, Q, F, Case, When, Value
from django.db.models.functions import Cast, Coalesce
import logging

logger = logging.getLogger(__name__)

def signup_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Validate input
        if not all([username, email, password, confirm_password]):
            messages.error(request, 'All fields are required. Please fill in your username, email, password, and confirm password.')
            return render(request, 'avc_app/signup.html')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match. Please ensure both password fields are identical.')
            return render(request, 'avc_app/signup.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, f'The username "{username}" is already taken. Please choose a different username.')
            return render(request, 'avc_app/signup.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, f'The email address "{email}" is already registered. Please use a different email or log in.')
            return render(request, 'avc_app/signup.html')

        # Create user with transaction to ensure atomicity
        try:
            with transaction.atomic():
                # Create the user
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password
                )
                # Create user profile
                UserProfile.objects.get_or_create(
                    user=user
                )
                messages.success(request, f'Account created successfully!')
                login(request, user)
                return redirect('dashboard')
        except IntegrityError as e:
            messages.error(request, f'Account creation failed due to a database error: {str(e)}. Please contact support if this persists.')
            logger.error(f'Error creating user account: {str(e)}')
            return render(request, 'avc_app/signup.html')
        except Exception as e:
            messages.error(request, f'An unexpected error occurred during signup: {str(e)}. Please try again or contact support.')
            logger.error(f'Unexpected error during signup: {str(e)}')
            return render(request, 'avc_app/signup.html')

    return render(request, 'avc_app/signup.html')

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def check_ip_security(ip_address):
    # Check if IP is blacklisted
    if IPBlacklist.objects.filter(ip_address=ip_address, is_active=True).exists():
        return False, "IP address is blacklisted"

    # Check rate limiting
    cache_key = f"ip_rate_limit_{ip_address}"
    request_count = cache.get(cache_key, 0)
    if request_count >= 5:  # Limit to 5 requests per minute
        return False, "Too many requests from this IP"
    cache.set(cache_key, request_count + 1, 60)  # 60 seconds expiry

    # Check for VPN/Proxy/VPS using IP intelligence API
    try:
        response = requests.get(
            f"https://ipapi.co/{ip_address}/json/",
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('proxy') or data.get('vpn') or data.get('hosting'):
                return False, "VPN/Proxy/VPS detected"
    except:
        pass  # Continue if API check fails

    return True, None

@login_required
def dashboard(request):
    # Only staff can create sessions
    show_session_form = request.user.is_staff
    session_form = None
    if show_session_form:
        if request.method == 'POST' and 'create_session' in request.POST:
            session_form = SessionForm(request.POST)
            if session_form.is_valid():
                session = session_form.save(commit=False)
                session.created_by = request.user
                session.save()
                session_form.save_m2m()
                messages.success(request, 'Session created successfully!')
                return redirect('dashboard')
            else:
                messages.error(request, 'Please correct the errors below in the session creation form. Check all required fields and try again.')
        else:
            session_form = SessionForm()
    elif request.method == 'POST' and 'create_session' in request.POST:
        messages.error(request, 'Only staff members are allowed to create sessions. If you believe this is an error, contact an administrator.')

    # Get current active session that the user is allowed to attend
    now = timezone.now()
    active_session = Session.objects.filter(
        is_active=True,
        start_time__lte=now,
        end_time__gte=now,
        allowed_users=request.user
    ).first()

    # Check if user has already marked attendance for this session
    current_attendance = None
    if active_session:
        current_attendance = AttendanceRecord.objects.filter(
            session=active_session,
            user=request.user
        ).first()

    # Get user's recent attendance history
    recent_attendance = AttendanceRecord.objects.filter(
        user=request.user
    ).select_related('session').order_by('-marked_at')[:5]

    # --- Analytics Section ---
    all_sessions = Session.objects.all()
    total_sessions = all_sessions.count()
    
    # Calculate attendance points
    attended_records = AttendanceRecord.objects.filter(user=request.user)
    attended_sessions = sum(1 for record in attended_records if record.is_valid)
    
    # Add points for approved absent permissions
    approved_absent_permissions = Permission.objects.filter(
        user=request.user,
        status='approved',
        reason='absent'
    ).count()
    attended_sessions += approved_absent_permissions * 0.5  # Add 0.5 for each approved absent permission
    
    attendance_percentage = int((attended_sessions / total_sessions) * 100) if total_sessions > 0 else 0
    is_eligible_for_sendforth = attendance_percentage >= 75
    
    # Get user's permission requests
    permission_requests = Permission.objects.filter(user=request.user).select_related('session').order_by('-created_at')
    
    attendance_stats = {
        'total_sessions': total_sessions,
        'attended_sessions': attended_sessions,
        'attendance_percentage': attendance_percentage,
        'is_eligible_for_sendforth': is_eligible_for_sendforth,
        'permission_requests': permission_requests,
    }
    # --- End Analytics Section ---

    context = {
        'active_session': active_session,
        'current_attendance': current_attendance,
        'recent_attendance': recent_attendance,
        'attendance_stats': attendance_stats,
        'session_form': session_form,
        'show_session_form': show_session_form,
    }
    return render(request, 'avc_app/dashboard.html', context)

@login_required
def mark_attendance(request, session_id):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    # Get session token from request
    session_token = request.POST.get('session_token')
    if not session_token:
        return JsonResponse({'error': 'Session token is required'}, status=400)

    # Get session and verify token
    try:
        session = Session.objects.get(
            id=session_id,
            is_active=True,
            session_token=session_token
        )
    except Session.DoesNotExist:
        return JsonResponse({'error': 'Invalid session or token'}, status=404)
    
    # Check if user is allowed to mark attendance for this session
    if not session.allowed_users.filter(id=request.user.id).exists():
        return JsonResponse({'error': 'You are not authorized to mark attendance for this session'}, status=403)

    # Check if session is currently active
    now = timezone.now()
    if not (session.start_time <= now <= session.end_time):
        return JsonResponse({'error': 'This session is not currently active'}, status=400)

    # Check if user has already marked attendance
    if AttendanceRecord.objects.filter(session=session, user=request.user).exists():
        return JsonResponse({'error': 'You have already marked attendance for this session'}, status=400)

    # Enhanced IP security checks
    ip_address = get_client_ip(request)
    is_safe, reason = check_ip_security(ip_address)
    if not is_safe:
        return JsonResponse({'error': reason}, status=403)

    # Additional IP validation
    if not validate_ip_address(ip_address):
        return JsonResponse({'error': 'Invalid IP address'}, status=403)

    # Create attendance record
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    if not user_agent:
        return JsonResponse({'error': 'Invalid request'}, status=400)

    try:
        attendance = AttendanceRecord.objects.create(
            session=session,
            user=request.user,
            ip_address=ip_address,
            user_agent=user_agent
        )
    except IntegrityError:
        return JsonResponse({'error': 'You have already marked attendance for this session.'}, status=400)

    return JsonResponse({
        'success': True,
        'message': 'Attendance marked successfully',
        'marked_at': attendance.marked_at.strftime('%Y-%m-%d %H:%M:%S')
    })

@login_required
def attendance_history(request):
    # Get attendance records with related data - fixed select_related
    attendance_records = AttendanceRecord.objects.filter(user=request.user).select_related("user", "user__profile", "session").order_by("-marked_at")
    # (We're no longer using "permission" in select_related; if you need permission data, you can prefetch it or query it separately.)

    # --- Analytics Section ---
    all_sessions = Session.objects.all()  # (Changed to match dashboard view)
    total_sessions = all_sessions.count()
    
    # Calculate attendance points – using same logic as dashboard (sum valid records and add 0.5 for approved absent permissions)
    attended_records = AttendanceRecord.objects.filter(user=request.user)
    attended_sessions = sum(1 for record in attended_records if record.is_valid)
    
    # (Add 0.5 for each approved absent permission)
    approved_absent_permissions = Permission.objects.filter(user=request.user, status="approved", reason="absent").count()
    attended_sessions += (approved_absent_permissions * 0.5)
    
    attendance_percentage = (int((attended_sessions / total_sessions) * 100) if total_sessions > 0 else 0)
    is_eligible_for_sendforth = (attendance_percentage >= 75)
    
    attendance_stats = { "total_sessions": total_sessions, "attended_sessions": attended_sessions, "attendance_percentage": attendance_percentage, "is_eligible_for_sendforth": is_eligible_for_sendforth }
    # --- End Analytics Section ---

    context = { "attendance_records": attendance_records, "attendance_stats": attendance_stats }
    return render(request, "avc_app/attendance_history.html", context)

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', 'dashboard')
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid username or password. Please check your credentials and try again.')
    
    return render(request, 'avc_app/login.html')

def logout_view(request):
    logout(request)
    messages.success(request, 'You have been successfully logged out.')
    return redirect('login')

@login_required
def request_permission(request):
    if request.method == 'POST':
        form = PermissionRequestForm(request.POST, user=request.user)
        if form.is_valid():
            # Check if user already has a permission request for this session
            session = form.cleaned_data['session']
            existing_permission = Permission.objects.filter(
                user=request.user,
                session=session
            ).first()
            
            if existing_permission:
                if existing_permission.status == 'pending':
                    messages.warning(request, f'You already have a pending permission request for this session. Please wait for it to be reviewed.')
                elif existing_permission.status == 'approved':
                    messages.warning(request, f'You already have an approved permission request for this session.')
                elif existing_permission.status == 'rejected':
                    # Allow new request if previous was rejected
                    try:
                        permission = form.save(commit=False)
                        permission.user = request.user
                        permission.save()
                        messages.success(request, 'Permission request submitted successfully.')
                        return redirect('dashboard')
                    except IntegrityError:
                        messages.error(request, 'A database error occurred while submitting your permission request. Please try again or contact support.')
                return redirect('request_permission')
            
            try:
                permission = form.save(commit=False)
                permission.user = request.user
                permission.save()
                messages.success(request, 'Permission request submitted successfully.')
                return redirect('dashboard')
            except IntegrityError:
                messages.error(request, 'A database error occurred while submitting your permission request. Please try again or contact support.')
    else:
        form = PermissionRequestForm(user=request.user)
    
    return render(request, 'avc_app/request_permission.html', {
        'form': form,
        'title': 'Request Permission'
    })

@login_required
def permission_list(request):
    # Get filter parameters
    status = request.GET.get('status')
    reason = request.GET.get('reason')
    date = request.GET.get('date')

    # Base queryset - staff see all, regular users see only their own
    permissions = Permission.objects.select_related(
        'user', 'user__profile', 'session', 'approved_by'
    )
    
    if not request.user.is_staff:
        permissions = permissions.filter(user=request.user)

    # Apply filters
    if status:
        permissions = permissions.filter(status=status)
    if reason:
        permissions = permissions.filter(reason=reason)
    if date:
        try:
            date_obj = datetime.strptime(date, '%Y-%m-%d').date()
            permissions = permissions.filter(session__start_time__date=date_obj)
        except ValueError:
            messages.error(request, 'Invalid date format. Please use YYYY-MM-DD.')

    # Order by most recent first
    permissions = permissions.order_by('-created_at')

    # Pagination
    paginator = Paginator(permissions, 10)  # Show 10 permissions per page
    page_number = request.GET.get('page')
    try:
        page_obj = paginator.get_page(page_number)
    except (PageNotAnInteger, EmptyPage):
        page_obj = paginator.get_page(1)
    
    # Get counts for filter options - only for staff
    if request.user.is_staff:
        status_counts = Permission.objects.values('status').annotate(count=Count('id'))
        reason_counts = Permission.objects.values('reason').annotate(count=Count('id'))
        
        status_counts = {item['status']: item['count'] for item in status_counts}
        reason_counts = {item['reason']: item['count'] for item in reason_counts}
    else:
        status_counts = permissions.values('status').annotate(count=Count('id'))
        reason_counts = permissions.values('reason').annotate(count=Count('id'))
        
        status_counts = {item['status']: item['count'] for item in status_counts}
        reason_counts = {item['reason']: item['count'] for item in reason_counts}
    
    context = {
        'permissions': page_obj,
        'page_obj': page_obj,
        'is_paginated': page_obj.has_other_pages(),
        'status_counts': status_counts,
        'reason_counts': reason_counts,
        'title': 'My Permission Requests' if not request.user.is_staff else 'Permission Requests',
        'current_filters': {
            'status': status,
            'reason': reason,
            'date': date,
        }
    }
    return render(request, 'avc_app/permission_list.html', context)

@login_required
@require_http_methods(['POST'])
def approve_permission(request, permission_id):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    
    permission = get_object_or_404(
        Permission.objects.select_related('user', 'session'),
        id=permission_id
    )
    
    # Check if permission is already processed
    if permission.status != 'pending':
        messages.warning(request, 'This permission request has already been processed.')
        return redirect('permission_list')
    
    form = PermissionApprovalForm(request.POST, instance=permission)
    
    if form.is_valid():
        try:
            with transaction.atomic():
                permission = form.save(commit=False)
                permission.approved_by = request.user
                permission.approved_at = timezone.now()
                permission.save()
                
                # Add appropriate message based on status
                if permission.status == 'approved':
                    messages.success(
                        request,
                        f'Permission request approved for {permission.user.get_full_name() or permission.user.username}.'
                    )
                else:
                    messages.info(
                        request,
                        f'Permission request rejected for {permission.user.get_full_name() or permission.user.username}.'
                    )
        except Exception as e:
            messages.error(request, f'Failed to process the permission request: {str(e)}. Please contact support if this continues.')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f'Field "{field}": {error}')
    
    return redirect('permission_list')

@login_required
@require_http_methods(['POST'])
def reject_permission(request, permission_id):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    
    permission = get_object_or_404(
        Permission.objects.select_related('user', 'session'),
        id=permission_id
    )
    
    # Check if permission is already processed
    if permission.status != 'pending':
        messages.warning(request, 'This permission request has already been processed.')
        return redirect('permission_list')
    
    form = PermissionApprovalForm(request.POST, instance=permission)
    
    if form.is_valid():
        try:
            with transaction.atomic():
                permission = form.save(commit=False)
                permission.status = 'rejected'  # Force status to rejected
                permission.approved_by = request.user
                permission.approved_at = timezone.now()
                permission.save()
                
                messages.info(
                    request,
                    f'Permission request rejected for {permission.user.get_full_name() or permission.user.username}.'
                )
        except Exception as e:
            messages.error(request, f'Failed to process the permission rejection: {str(e)}. Please contact support if this continues.')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f'Field "{field}": {error}')
    
    return redirect('permission_list')

@login_required
def export_permissions_csv(request):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    
    # Create the HttpResponse object with CSV header
    response = HttpResponse(
        content_type='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename="permission_records_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        }
    )
    
    # Create CSV writer with proper encoding
    writer = csv.writer(response, quoting=csv.QUOTE_ALL)
    
    # Write headers
    writer.writerow([
        'Request ID', 'Student Name', 'Session', 'Session Date',
        'Reason', 'Explanation', 'Status', 'Admin Comment', 'Requested At',
        'Processed By', 'Processed At'
    ])
    
    # Get all permissions with related data
    permissions = Permission.objects.select_related(
        'user', 'user__profile', 'session', 'approved_by'
    ).order_by('-created_at')
    
    # Write data rows
    for perm in permissions:
        try:
            writer.writerow([
                perm.id,
                perm.user.get_full_name() or perm.user.username,
                perm.session.name,
                perm.session.start_time.strftime('%Y-%m-%d %H:%M'),
                perm.get_reason_display(),
                perm.explanation,
                perm.get_status_display(),
                perm.admin_comment or '',
                perm.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                perm.approved_by.get_full_name() if perm.approved_by else '',
                perm.approved_at.strftime('%Y-%m-%d %H:%M:%S') if perm.approved_at else ''
            ])
        except Exception as e:
            # Log the error but continue processing
            logger.error(f'Error exporting permission {perm.id}: {str(e)}')
            continue
    
    return response

from django.http import StreamingHttpResponse

@login_required
def export_attendance_csv(request):
    if not request.user.is_staff:
        return HttpResponseForbidden()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"attendance_records_{timestamp}.csv"

    records = AttendanceRecord.objects.select_related(
        'user', 'user__profile', 'session'
    ).order_by('-marked_at')

    # Preload permissions
    permissions_lookup = {
        (perm.session_id, perm.user_id): perm
        for perm in Permission.objects.select_related('approved_by').all()
    }

    # Generator function for streaming
    def row_generator():
        yield [
            'Record ID', 'Student Name', 'Session', 'Session Date',
            'Status', 'Permission Status', 'Permission Reason',
            'Admin Comment', 'Marked At', 'IP Address', 'Valid'
        ]
        for record in records.iterator():  # Use iterator to reduce memory
            perm = permissions_lookup.get((record.session_id, record.user_id))
            yield [
                record.id,
                record.user.get_full_name() or record.user.username,
                record.session.name,
                record.session.start_time.strftime('%Y-%m-%d %H:%M'),
                'Present' if record.is_valid else 'Absent',
                perm.get_status_display() if perm else 'N/A',
                perm.get_reason_display() if perm else 'N/A',
                perm.admin_comment if perm and perm.admin_comment else '',
                record.marked_at.strftime('%Y-%m-%d %H:%M:%S'),
                record.ip_address,
                'Yes' if record.is_valid else 'No',
            ]

    # Stream response
    class Echo:
        def write(self, value):
            return value

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer, quoting=csv.QUOTE_ALL)

    response = StreamingHttpResponse(
        (writer.writerow(row) for row in row_generator()),
        content_type='text/csv'
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

def handler404(request, exception):
    return render(request, 'avc_app/404.html', status=404)

def handler500(request):
    return render(request, 'avc_app/500.html', status=500)

def handler403(request, exception):
    return render(request, 'avc_app/403.html', status=403)

def handler400(request, exception):
    return render(request, 'avc_app/400.html', status=400)
