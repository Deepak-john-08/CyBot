from django.db import models
from django.utils import timezone

class PhishingEmail(models.Model):
    """Store phishing email detection results"""
    email_content = models.TextField()
    sender = models.EmailField(blank=True, null=True)
    subject = models.CharField(max_length=500, blank=True, null=True)
    is_phishing = models.BooleanField()
    confidence_score = models.FloatField()
    rule_based_score = models.FloatField()
    ml_score = models.FloatField()
    detection_method = models.CharField(max_length=50)  # 'rule', 'ml', 'hybrid'
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-created_at']

class PhishingURL(models.Model):
    """Store phishing URL detection results"""
    url = models.URLField(max_length=2000)
    domain = models.CharField(max_length=255)
    is_phishing = models.BooleanField()
    confidence_score = models.FloatField()
    rule_based_score = models.FloatField()
    ml_score = models.FloatField()
    detection_method = models.CharField(max_length=50)
    url_features = models.JSONField(default=dict)  # Store extracted features
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-created_at']

class TrainingData(models.Model):
    """Store training data for ML models"""
    CONTENT_TYPES = [
        ('email', 'Email'),
        ('url', 'URL'),
    ]
    
    content = models.TextField()
    content_type = models.CharField(max_length=10, choices=CONTENT_TYPES)
    is_phishing = models.BooleanField()
    source = models.CharField(max_length=100, blank=True)  # Where data came from
    verified = models.BooleanField(default=False)  # Human verified
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-created_at']

class ModelPerformance(models.Model):
    """Track model performance metrics"""
    model_name = models.CharField(max_length=100)
    model_type = models.CharField(max_length=50)  # 'email', 'url'
    accuracy = models.FloatField()
    precision = models.FloatField()
    recall = models.FloatField()
    f1_score = models.FloatField()
    training_date = models.DateTimeField(default=timezone.now)
    model_path = models.CharField(max_length=500, blank=True)
    
  
