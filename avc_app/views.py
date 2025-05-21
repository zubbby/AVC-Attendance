from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from .user_profile import UserProfile
import requests
import json
from .models import Session, AttendanceRecord, IPBlacklist, Permission
from django.utils import timezone
import qrcode
from io import BytesIO
import base64
import secrets
from .utils import get_client_ip, check_ip_security, validate_ip_address
from django.db import IntegrityError
from .forms import PermissionRequestForm, PermissionApprovalForm
from django.core.paginator import Paginator

def signup_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Validate input
        if not all([username, email, password, confirm_password]):
            messages.error(request, 'All fields are required.')
            return render(request, 'avc_app/signup.html')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'avc_app/signup.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return render(request, 'avc_app/signup.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'avc_app/signup.html')

        # Create user
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            # UserProfile will be automatically created via signal
            messages.success(request, f'Account created successfully! Your AVC ID is {user.profile.avc_id}')
            login(request, user)
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error creating account: {str(e)}')
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
    # Get attendance records with related permissions
    attendance_records = AttendanceRecord.objects.filter(
        user=request.user
    ).select_related('session', 'permission', 'permission__approved_by').order_by('-marked_at')

    # --- Analytics Section ---
    all_sessions = Session.objects.filter(allowed_users=request.user)
    total_sessions = all_sessions.count()
    
    # Calculate attendance points
    attended_sessions = sum(1 for record in attendance_records if record.is_valid)
    
    # Add points for approved absent permissions
    approved_absent_permissions = Permission.objects.filter(
        user=request.user,
        status='approved',
        reason='absent'
    ).count()
    attended_sessions += approved_absent_permissions * 0.5  # Add 0.5 for each approved absent permission
    
    attendance_percentage = int((attended_sessions / total_sessions) * 100) if total_sessions > 0 else 0
    is_eligible_for_sendforth = attendance_percentage >= 75
    
    attendance_stats = {
        'total_sessions': total_sessions,
        'attended_sessions': attended_sessions,
        'attendance_percentage': attendance_percentage,
        'is_eligible_for_sendforth': is_eligible_for_sendforth,
    }
    # --- End Analytics Section ---

    context = {
        'attendance_records': attendance_records,
        'attendance_stats': attendance_stats,
    }
    return render(request, 'avc_app/attendance_history.html', context)

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
            messages.error(request, 'Invalid username or password.')
    
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
            permission = form.save(commit=False)
            permission.user = request.user
            permission.save()
            messages.success(request, 'Permission request submitted successfully.')
            return redirect('dashboard')
    else:
        form = PermissionRequestForm(user=request.user)
    
    return render(request, 'avc_app/request_permission.html', {
        'form': form,
        'title': 'Request Permission'
    })

@login_required
def permission_list(request):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    
    # Get filter parameters
    status = request.GET.get('status')
    reason = request.GET.get('reason')
    date = request.GET.get('date')
    
    # Start with base queryset
    permissions = Permission.objects.all().select_related('user', 'session', 'approved_by')
    
    # Apply filters
    if status:
        permissions = permissions.filter(status=status)
    if reason:
        permissions = permissions.filter(reason=reason)
    if date:
        permissions = permissions.filter(created_at__date=date)
    
    # Order by created_at
    permissions = permissions.order_by('-created_at')
    
    # Pagination
    paginator = Paginator(permissions, 10)  # Show 10 permissions per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get counts for filter options
    status_counts = {
        'pending': Permission.objects.filter(status='pending').count(),
        'approved': Permission.objects.filter(status='approved').count(),
        'rejected': Permission.objects.filter(status='rejected').count(),
    }
    
    reason_counts = {
        'late': Permission.objects.filter(reason='late').count(),
        'absent': Permission.objects.filter(reason='absent').count(),
    }
    
    context = {
        'permissions': page_obj,
        'page_obj': page_obj,  # For pagination template
        'is_paginated': page_obj.has_other_pages(),
        'status_counts': status_counts,
        'reason_counts': reason_counts,
        'title': 'Permission Requests',
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
    
    permission = get_object_or_404(Permission, id=permission_id)
    form = PermissionApprovalForm(request.POST, instance=permission)
    
    if form.is_valid():
        permission = form.save(commit=False)
        permission.approved_by = request.user
        permission.save()
        messages.success(request, f'Permission request {permission.get_status_display().lower()}.')
    else:
        messages.error(request, 'Invalid form submission.')
    
    return redirect('permission_list')

from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from .user_profile import UserProfile
import requests
import json
from .models import Session, AttendanceRecord, IPBlacklist, Permission
from django.utils import timezone
import qrcode
from io import BytesIO
import base64
import secrets
from .utils import get_client_ip, check_ip_security, validate_ip_address
from django.db import IntegrityError
from .forms import PermissionRequestForm, PermissionApprovalForm
from django.core.paginator import Paginator

def signup_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Validate input
        if not all([username, email, password, confirm_password]):
            messages.error(request, 'All fields are required.')
            return render(request, 'avc_app/signup.html')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'avc_app/signup.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return render(request, 'avc_app/signup.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'avc_app/signup.html')

        # Create user
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            # UserProfile will be automatically created via signal
            messages.success(request, f'Account created successfully! Your AVC ID is {user.profile.avc_id}')
            login(request, user)
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error creating account: {str(e)}')
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
    attended_records = AttendanceRecord.objects.filter(user=request.user)
    attended_sessions = sum(1 for record in attended_records if record.is_valid)
    
    # Add approved absent permissions to attended sessions
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
    attendance_records = AttendanceRecord.objects.filter(
        user=request.user
    ).select_related('session').order_by('-marked_at')

    # --- Analytics Section ---
    all_sessions = Session.objects.filter(allowed_users=request.user)
    total_sessions = all_sessions.count()
    attended_sessions = sum(1 for record in attendance_records if record.is_valid)
    attendance_percentage = int((attended_sessions / total_sessions) * 100) if total_sessions > 0 else 0
    is_eligible_for_sendforth = attendance_percentage >= 75
    attendance_stats = {
        'total_sessions': total_sessions,
        'attended_sessions': attended_sessions,
        'attendance_percentage': attendance_percentage,
        'is_eligible_for_sendforth': is_eligible_for_sendforth,
    }
    # --- End Analytics Section ---

    context = {
        'attendance_records': attendance_records,
        'attendance_stats': attendance_stats,
    }
    return render(request, 'avc_app/attendance_history.html', context)

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
            messages.error(request, 'Invalid username or password.')
    
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
            permission = form.save(commit=False)
            permission.user = request.user
            permission.save()
            messages.success(request, 'Permission request submitted successfully.')
            return redirect('dashboard')
    else:
        form = PermissionRequestForm(user=request.user)
    
    return render(request, 'avc_app/request_permission.html', {
        'form': form,
        'title': 'Request Permission'
    })

@login_required
def permission_list(request):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    
    # Get filter parameters
    status = request.GET.get('status')
    reason = request.GET.get('reason')
    date = request.GET.get('date')
    
    # Start with base queryset
    permissions = Permission.objects.all().select_related('user', 'session', 'approved_by')
    
    # Apply filters
    if status:
        permissions = permissions.filter(status=status)
    if reason:
        permissions = permissions.filter(reason=reason)
    if date:
        permissions = permissions.filter(created_at__date=date)
    
    # Order by created_at
    permissions = permissions.order_by('-created_at')
    
    # Pagination
    paginator = Paginator(permissions, 10)  # Show 10 permissions per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get counts for filter options
    status_counts = {
        'pending': Permission.objects.filter(status='pending').count(),
        'approved': Permission.objects.filter(status='approved').count(),
        'rejected': Permission.objects.filter(status='rejected').count(),
    }
    
    reason_counts = {
        'late': Permission.objects.filter(reason='late').count(),
        'absent': Permission.objects.filter(reason='absent').count(),
    }
    
    context = {
        'permissions': page_obj,
        'page_obj': page_obj,  # For pagination template
        'is_paginated': page_obj.has_other_pages(),
        'status_counts': status_counts,
        'reason_counts': reason_counts,
        'title': 'Permission Requests',
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
    
    permission = get_object_or_404(Permission, id=permission_id)
    form = PermissionApprovalForm(request.POST, instance=permission)
    
    if form.is_valid():
        permission = form.save(commit=False)
        permission.approved_by = request.user
        permission.save()
        messages.success(request, f'Permission request {permission.get_status_display().lower()}.')
    else:
        messages.error(request, 'Invalid form submission.')
    
    return redirect('permission_list')
