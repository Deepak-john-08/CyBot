from django.urls import path
from .views import chatbot_view, chatbot_page, upload_pdf_view, login_view, logout_view, register_view

urlpatterns = [
    path('', login_view, name='login'),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    path('chatbot/', chatbot_view, name='chatbot'),
    path('chat/', chatbot_page, name='chatbot_page'),
    path('upload_pdf/', upload_pdf_view, name='upload_pdf'),
] 