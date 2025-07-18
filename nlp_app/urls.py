from django.urls import path
from .views import chatbot_view, chatbot_page, upload_pdf_view

urlpatterns = [
    path('chatbot/', chatbot_view, name='chatbot'),
    path('chat/', chatbot_page, name='chatbot_page'),
    path('upload_pdf/', upload_pdf_view, name='upload_pdf'),
] 