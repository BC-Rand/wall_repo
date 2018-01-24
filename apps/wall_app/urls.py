from django.conf.urls import url
from . import views
urlpatterns = [
    url(r'^$', views.index),
    url(r'^register/$', views.register),
    url(r'^process_reg/$', views.process_reg),
    url(r'^dashboard/$', views.dashboard),
    url(r'^dashboard/admin', views.dashboard_admin),
    url(r'^login/$', views.login),
    url(r'^process_log/$', views.process_log),
    url(r'^logout/$', views.logout),
    url(r'^users/show/(?P<number>\d+)', views.users_show_id),
    url(r'^process_msg/$', views.process_msg),
    url(r'^process_cmt/$', views.process_cmt),
    url(r'^users/edit/(?P<number>\d+)', views.users_edit_id),
    url(r'^process_edit_info', views.process_edit_info),
    url(r'^process_pw_change', views.process_pw_change),
    url(r'^process_desc_change', views.process_desc_change),
    url(r'^users/new', views.users_new),
    url(r'^process_users_new/$', views.process_users_new),
    url(r'^admin/edit/(?P<number>\d+)', views.admin_edit_id),
    url(r'^admin/destroy/(?P<number>\d+)', views.admin_destroy_id),
    url(r'^process_admin_edit_info', views.process_admin_edit_info),
    url(r'^process_admin_destroy', views.process_admin_destroy)
]