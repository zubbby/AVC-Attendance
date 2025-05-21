from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('mark-attendance/<int:session_id>/', views.mark_attendance, name='mark_attendance'),
    path('attendance-history/', views.attendance_history, name='attendance_history'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('signup/', views.signup_view, name='signup'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('mark-attendance/', views.mark_attendance, name='mark_attendance'),
    path('request-permission/', views.request_permission, name='request_permission'),
    path('permissions/', views.permission_list, name='permission_list'),
    path('permissions/<int:permission_id>/approve/', views.approve_permission, name='approve_permission'),
    path('export/permissions/', views.export_permissions_csv, name='export_permissions_csv'),
    path('export/attendance/', views.export_attendance_csv, name='export_attendance_csv'),
] 
