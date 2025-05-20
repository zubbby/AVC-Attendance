from django.core.cache import cache
import requests
import ipaddress
from .models import IPBlacklist
from django.conf import settings
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Get the first IP in the chain
        ip = x_forwarded_for.split(',')[0].strip()
        logger.info(f"Got IP from X-Forwarded-For: {ip}")
    else:
        ip = request.META.get('REMOTE_ADDR')
        logger.info(f"Got IP from REMOTE_ADDR: {ip}")
    
    # Log all request headers for debugging
    logger.info("Request headers:")
    for header, value in request.META.items():
        if header.startswith('HTTP_'):
            logger.info(f"{header}: {value}")
    
    # Additional validation
    if not ip:
        logger.error("No IP address found in request")
        return None
        
    if not validate_ip_address(ip):
        logger.error(f"IP validation failed for: {ip}")
        return None
        
    logger.info(f"Valid IP address: {ip}")
    return ip

def validate_ip_address(ip):
    try:
        logger.info(f"Validating IP: {ip}")
        # Check if it's a valid IP address
        ip_obj = ipaddress.ip_address(ip)
        
        # Log IP properties
        logger.info(f"IP properties - Private: {ip_obj.is_private}, Loopback: {ip_obj.is_loopback}, Multicast: {ip_obj.is_multicast}")
        
        # Allow private IPs in all environments
        # Only reject loopback and multicast, except allow loopback in development
        if ip_obj.is_loopback:
            if getattr(settings, 'DEBUG', False):
                logger.info(f"Loopback IP allowed in DEBUG mode: {ip}")
            else:
                logger.warning(f"Loopback IP rejected: {ip}")
                return False
        if ip_obj.is_multicast:
            logger.warning(f"Multicast IP rejected: {ip}")
            return False
            
        logger.info(f"IP validation successful: {ip}")
        return True
    except ValueError as e:
        logger.error(f"IP validation error for {ip}: {str(e)}")
        return False

def check_ip_security(ip_address):
    if not ip_address or not validate_ip_address(ip_address):
        return False, "Invalid IP address"

    # Check if IP is blacklisted
    if IPBlacklist.objects.filter(ip_address=ip_address, is_active=True).exists():
        return False, "IP address is blacklisted"

    # Check rate limiting with more granular control
    cache_key = f"ip_rate_limit_{ip_address}"
    request_count = cache.get(cache_key, 0)
    
    # More strict rate limiting for attendance marking
    if request_count >= 3:  # Limit to 3 requests per minute
        return False, "Too many requests from this IP"
    
    # Increment counter with shorter expiry
    cache.set(cache_key, request_count + 1, 30)  # 30 seconds expiry

    # Enhanced VPN/Proxy/VPS detection using multiple services
    vpn_detected = False
    vpn_reason = None

    # Check 1: ipapi.co
    try:
        response = requests.get(
            f"https://ipapi.co/{ip_address}/json/",
            timeout=5,
            headers={'User-Agent': 'AVC Attendance System'}
        )
        if response.status_code == 200:
            data = response.json()
            
            # Check for VPN/Proxy
            if data.get('proxy') or data.get('vpn'):
                vpn_detected = True
                vpn_reason = "VPN/Proxy detected"
                
            # Check for hosting/VPS
            if data.get('hosting'):
                vpn_detected = True
                vpn_reason = "VPS/Hosting detected"
                
            # Check for mobile/carrier IPs
            if data.get('mobile'):
                vpn_detected = True
                vpn_reason = "Mobile network detected"
                
            # Check for datacenter IPs
            if data.get('org', '').lower() in ['amazon', 'google', 'microsoft', 'digitalocean', 'linode', 'vultr', 'ovh', 'rackspace', 'ibm', 'oracle']:
                vpn_detected = True
                vpn_reason = "Datacenter IP detected"

            # Check for known VPN providers
            vpn_providers = [
                'expressvpn', 'nordvpn', 'cyberghost', 'surfshark', 'protonvpn', 
                'private internet access', 'ipvanish', 'tunnelbear', 'windscribe',
                'mullvad', 'hide.me', 'purevpn', 'vpn.ac', 'vpnunlimited', 'vyprvpn',
                'strongvpn', 'perfect privacy', 'airvpn', 'cactusvpn', 'vpnsecure',
                'trust.zone', 'vpn.ht', 'vpnarea', 'vpnjack', 'vpnsecure.me'
            ]
            org_name = data.get('org', '').lower()
            if any(provider in org_name for provider in vpn_providers):
                vpn_detected = True
                vpn_reason = "Known VPN provider detected"

    except:
        # If first API check fails, try backup service
        try:
            # Check 2: ipinfo.io (backup service)
            response = requests.get(
                f"https://ipinfo.io/{ip_address}/json",
                timeout=5,
                headers={'User-Agent': 'AVC Attendance System'}
            )
            if response.status_code == 200:
                data = response.json()
                
                # Check for VPN/Proxy
                if data.get('privacy', {}).get('proxy') or data.get('privacy', {}).get('vpn'):
                    vpn_detected = True
                    vpn_reason = "VPN/Proxy detected (backup check)"
                
                # Check for hosting
                if data.get('privacy', {}).get('hosting'):
                    vpn_detected = True
                    vpn_reason = "Hosting detected (backup check)"
                
                # Check for known VPN providers
                if data.get('org', '').lower() in vpn_providers:
                    vpn_detected = True
                    vpn_reason = "Known VPN provider detected (backup check)"

        except:
            # If both API checks fail, be strict
            return False, "Unable to verify IP address security"

    if vpn_detected:
        # Add IP to blacklist for 24 hours
        IPBlacklist.objects.create(
            ip_address=ip_address,
            reason=f"VPN detected: {vpn_reason}",
            expires_at=timezone.now() + timezone.timedelta(hours=24)
        )
        return False, vpn_reason

    return True, None 