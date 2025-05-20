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
from .models import Session, AttendanceRecord, IPBlacklist
from django.utils import timezone
import qrcode
from io import BytesIO
import base64
import secrets
from .utils import get_client_ip, check_ip_security, validate_ip_address
from django.db import IntegrityError

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
    all_sessions = Session.objects.filter(allowed_users=request.user)
    total_sessions = all_sessions.count()
    attended_records = AttendanceRecord.objects.filter(user=request.user)
    attended_sessions = sum(1 for record in attended_records if record.is_valid)
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
