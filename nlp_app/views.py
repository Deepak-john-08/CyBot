from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.shortcuts import render
import json
import re
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

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

# Load DialoGPT model and tokenizer globally
try:
    tokenizer = AutoTokenizer.from_pretrained("microsoft/DialoGPT-medium")
    model = AutoModelForCausalLM.from_pretrained("microsoft/DialoGPT-medium")
except Exception as e:
    tokenizer = None
    model = None

def ml_fallback_response(user_message, chat_history_ids=None):
    if not tokenizer or not model:
        return "Sorry, the AI model is not available right now.", None
    new_input_ids = tokenizer.encode(user_message + tokenizer.eos_token, return_tensors='pt')
    bot_input_ids = torch.cat([chat_history_ids, new_input_ids], dim=-1) if chat_history_ids is not None else new_input_ids
    chat_history_ids = model.generate(bot_input_ids, max_length=1000, pad_token_id=tokenizer.eos_token_id)
    response = tokenizer.decode(chat_history_ids[:, bot_input_ids.shape[-1]:][0], skip_special_tokens=True)
    return response, chat_history_ids

def rule_based_response(user_message):
    rules = [
        (r'spoofing', "Spoofing is a cyberattack where someone pretends to be a trusted source to gain access to sensitive information."),
        (r'sniffing', "Sniffing is the act of monitoring and capturing data packets passing through a network, often used to steal information."),
        (r'phishing', "Phishing is a scam where attackers trick you into giving up sensitive information by pretending to be a trustworthy entity."),
        (r'social engineering', "Social engineering is manipulating people into giving up confidential information, often by pretending to be someone trustworthy."),
        (r'malware', "Malware is malicious software designed to harm, exploit, or otherwise compromise a computer system."),
        (r'ransomware', "Ransomware is a type of malware that locks or encrypts your files and demands payment for their release."),
        (r'firewall', "A firewall is a security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules."),
        (r'virus', "A computer virus is a type of malware that attaches itself to a program or file and can spread from one computer to another."),
        (r'trojan', "A trojan is a type of malware disguised as legitimate software, used by cybercriminals to gain access to users' systems."),
        (r'botnet', "A botnet is a network of infected computers controlled by a hacker to perform tasks like sending spam or launching attacks."),
        (r'zero[- ]day', "A zero-day is a vulnerability in software that is unknown to the vendor and has not been patched, making it a target for attacks."),
        (r'brute[- ]force', "A brute-force attack is when an attacker tries many passwords or keys with the hope of eventually guessing correctly."),
        (r'encryption', "Encryption is the process of converting information into a code to prevent unauthorized access."),
        (r'2fa|two[- ]factor|multi[- ]factor', "Two-factor authentication (2FA) adds an extra layer of security by requiring two forms of identification to access an account."),
        (r'vpn', "A VPN (Virtual Private Network) encrypts your internet connection and hides your IP address for privacy and security."),
        (r'patch', "A patch is a software update that fixes security vulnerabilities and other bugs."),
        (r'update', "Always keep your software and antivirus updated to protect against threats."),
        (r'password', "Never share your password with anyone. Use strong, unique passwords for each account."),
        (r'cybersecurity', "Cybersecurity is the practice of protecting systems, networks, and programs from digital attacks."),
        (r'firewall', "A firewall is a network security device that monitors and filters incoming and outgoing network traffic."),
        (r'backdoor', "A backdoor is a method of bypassing normal authentication to gain access to a system, often left by malware."),
        (r'spyware', "Spyware is software that secretly monitors and collects user information without their knowledge."),
        (r'adware', "Adware is software that automatically displays or downloads advertising material when a user is online."),
        (r'rootkit', "A rootkit is a collection of software tools that enable unauthorized access to a computer or network."),
        (r'ddos', "A DDoS (Distributed Denial of Service) attack overwhelms a system with traffic to make it unavailable to users."),
        (r'authentication', "Authentication is the process of verifying the identity of a user or device."),
        (r'authorization', "Authorization is the process of giving someone permission to do or have something."),
        (r'breach', "A breach is an incident where information is stolen or taken from a system without the knowledge or authorization of the system's owner."),
        (r'cookie', "A cookie is a small piece of data stored on the user's computer by the web browser while browsing a website."),
        (r'certificate', "A digital certificate is an electronic document used to prove the ownership of a public key."),
        (r'public key', "A public key is used in cryptography to encrypt messages that only the holder of the paired private key can decrypt."),
        (r'private key', "A private key is a secret key used in cryptography to decrypt messages encrypted with the paired public key."),
    ]
    for pattern, response in rules:
        if re.search(pattern, user_message, re.IGNORECASE):
            return response
    return None

@csrf_exempt
def chatbot_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_message = data.get('message', '').lower()
        except Exception:
            return JsonResponse({'error': 'Invalid input.'}, status=400)

        # Rule-based logic (expanded)
        rule_response = rule_based_response(user_message)
        if rule_response:
            return JsonResponse({'response': rule_response})

        if (
            'subject:' in user_message and 'from:' in user_message and 'to:' in user_message
        ) or (
            'dear customer' in user_message or 'dear user' in user_message
        ):
            is_phishing, result = detect_phishing_email(user_message)
            return JsonResponse({'response': result, 'phishing': is_phishing})
        elif 'http' in user_message or 'www.' in user_message:
            is_phishing, result = detect_phishing_link(user_message)
            return JsonResponse({'response': result, 'phishing': is_phishing})

        # ML/NLP fallback
        ml_response, _ = ml_fallback_response(user_message)
        return JsonResponse({'response': ml_response})
    else:
        return JsonResponse({'error': 'POST request required.'}, status=405)

def chatbot_page(request):
    return render(request, 'nlp_app/chatbot.html')
