from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('signup/', views.signup_view, name='signup'),
    path('history/', views.attendance_history, name='attendance_history'),
    path('request-permission/', views.request_permission, name='request_permission'),
    path('permissions/', views.permission_list, name='permission_list'),
    path('permissions/<int:permission_id>/approve/', views.approve_permission, name='approve_permission'),
    path('permissions/<int:permission_id>/reject/', views.reject_permission, name='reject_permission'),
    path('export/permissions/', views.export_permissions_csv, name='export_permissions_csv'),
    path('export/attendance/', views.export_attendance_csv, name='export_attendance_csv'),
] 
