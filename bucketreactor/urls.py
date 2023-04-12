from django.urls import re_path
from rest_framework.urlpatterns import format_suffix_patterns

from . import views

urlpatterns = (
    # Public
    re_path(r'^$', views.root),
    
    re_path(r'^user/auth/register/$', views.RegisterView.as_view(), name='user-register'),
    re_path(r'^user/auth/login/$', views.LoginView.as_view(), name='user-login'),
    re_path(r'^user/auth/logout/$', views.LogoutView.as_view(), name='user-logout'),
    re_path(r'^user/auth/password/change/$', views.PasswordChangeView.as_view(), name='user-password-change'),
    re_path(r'^user/auth/password/reset/$', views.PasswordResetView.as_view(), name='user-password-reset'),

    re_path(r'^user/box/$', views.BoxListCreateView.as_view(), name='user-node-view'),
    re_path(r'^user/box/(?P<identifier>([a-zA-Z0-9\_\-]+))/$', views.BoxUpdateView.as_view(), name='user-node-update'),
    re_path(r'^user/box/(?P<identifier>([a-zA-Z0-9\_\-]+))/measure/$', views.MeasurementListCreateView.as_view(), name='user-node-update')
)

urlpatterns = format_suffix_patterns(urlpatterns)
