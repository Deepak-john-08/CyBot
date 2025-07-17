from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.shortcuts import render
import json
import re

# --- Improved Phishing detection stubs ---
def detect_phishing_email(email_text):
    # Rule-based phishing detection for emails
    phishing_keywords = [
        "urgent", "verify your account", "login to your account", "update your information", "suspended",
        "confirm your identity", "click the link below", "act now", "immediate action required", "reset your password",
        "security alert", "unusual activity", "account locked", "provide your credentials", "bank account"
    ]
    suspicious_phrases = [
        "dear customer", "dear user", "dear valued customer", "greetings from", "official notice"
    ]
    suspicious_senders = [
        "noreply@", "support@", "admin@", "service@", "security@"
    ]
    score = 0
    for keyword in phishing_keywords:
        if keyword in email_text.lower():
            score += 2
    for phrase in suspicious_phrases:
        if phrase in email_text.lower():
            score += 1
    for sender in suspicious_senders:
        if sender in email_text.lower():
            score += 1
    if score >= 3:
        return True, "Warning: This email contains multiple signs of phishing. Do not click any links or provide personal information."
    elif score == 2:
        return True, "Caution: This email may be a phishing attempt. Be careful."
    else:
        return False, "This email does not appear to be phishing, but always stay vigilant."

def detect_phishing_link(link):
    # Rule-based phishing detection for links
    suspicious_patterns = [
        r"bit\.ly", r"tinyurl", r"free-.*\.com", r"login-.*\.secure", r"secure-.*\.com", r"account-.*\.com",
        r"\d{1,3}(?:\.\d{1,3}){3}",  # IP address in URL
        r"paypal-.*\.com", r"bank-.*\.com", r"update-.*\.com", r"verify-.*\.com",
        r"[a-zA-Z0-9]+\.(ru|cn|tk|ml|ga|cf|gq|xyz)"  # suspicious TLDs
    ]
    misspelled_brands = [
        "paypa1", "faceb00k", "g00gle", "micros0ft", "amaz0n", "app1e"
    ]
    score = 0
    for pattern in suspicious_patterns:
        if re.search(pattern, link.lower()):
            score += 2
    for brand in misspelled_brands:
        if brand in link.lower():
            score += 2
    if score >= 3:
        return True, "Warning: This link is highly suspicious and may be a phishing attempt. Do not click it."
    elif score == 2:
        return True, "Caution: This link may be a phishing attempt. Be careful."
    else:
        return False, "This link does not appear to be phishing, but always check the URL carefully."

@csrf_exempt
def chatbot_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_message = data.get('message', '').lower()
        except Exception:
            return JsonResponse({'error': 'Invalid input.'}, status=400)

        # --- Intent detection ---
        if 'phishing' in user_message and ('email' in user_message or 'mail' in user_message):
            is_phishing, result = detect_phishing_email(user_message)
            return JsonResponse({'response': result, 'phishing': is_phishing})
        elif 'phishing' in user_message and ('link' in user_message or 'url' in user_message):
            is_phishing, result = detect_phishing_link(user_message)
            return JsonResponse({'response': result, 'phishing': is_phishing})
        elif 'http' in user_message or 'www.' in user_message:
            is_phishing, result = detect_phishing_link(user_message)
            return JsonResponse({'response': result, 'phishing': is_phishing})
        elif 'password' in user_message:
            response = "Never share your password with anyone. Use strong, unique passwords for each account."
        elif 'phishing' in user_message:
            response = "Phishing is a type of online scam. Be cautious of suspicious emails or links."
        elif 'update' in user_message:
            response = "Always keep your software and antivirus updated to protect against threats."
        else:
            response = "I'm your cybersecurity assistant! Ask me about online safety, phishing, passwords, and more."

        return JsonResponse({'response': response})
    else:
        return JsonResponse({'error': 'POST request required.'}, status=405)

def chatbot_page(request):
    return render(request, 'nlp_app/chatbot.html')
