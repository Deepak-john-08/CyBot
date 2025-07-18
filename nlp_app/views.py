from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.shortcuts import render
import json
import re
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from dotenv import load_dotenv
import os
import requests

load_dotenv()  # This will load variables from .env into os.environ

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

# Remove DialoGPT and langchain fallback, add Ollama TinyLlama fallback

GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # Store your key in .env

def groq_response(user_message, model_name="llama3-70b-8192"):
    print("GROQ_API_KEY:", GROQ_API_KEY)
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity expert assistant. Always answer the user's specific question directly and concisely. "
                    "If the user asks for a definition, provide a clear and accurate definition of the exact term they mention, not a general topic."
                )
            },
            {"role": "user", "content": user_message}
        ]
    }
    print("Sending to Groq:", data)
    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"]
    except Exception as e:
        print("Groq API error:", e)
        return f"Error contacting Groq: {e}"

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
        (r'(how|steps?|tips?) (to|for)? (create|make|choose|set) (a )?strong password',
         "Here are steps to create a strong password:\n"
         "1. Use at least 12 characters (the longer, the better).\n"
         "2. Mix uppercase, lowercase, numbers, and symbols.\n"
         "3. Avoid common words, names, or easily guessed info.\n"
         "4. Don’t reuse passwords across sites.\n"
         "5. Consider using a passphrase or a password manager."),
        (r'what is (a )?strong password',
         "A strong password is long (at least 12 characters), uses a mix of letters, numbers, and symbols, and avoids common words or patterns."),
        (r'strong password',
         "A strong password should be at least 12 characters, include uppercase and lowercase letters, numbers, and symbols, and not use common words or personal info."),
        (r'password',
         "Never share your password with anyone. Use strong, unique passwords for each account."),
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

# Ollama fallback for local models (Mistral or Llama2)
def ollama_response(user_message, model_name="llama2"):
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model_name,
                "prompt": user_message,
                "stream": False
            },
            timeout=60
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response", f"Sorry, I couldn't generate a response with {model_name}.")
    except Exception as e:
        return f"Error contacting Ollama ({model_name}): {e}"

@csrf_exempt
def chatbot_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_message = data.get('message', '')  # Do not lowercase
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

        # Groq fallback (Llama 3 70B as default)
        groq_api_response = groq_response(user_message, model_name="llama3-70b-8192")
        return JsonResponse({'response': groq_api_response})
    else:
        return JsonResponse({'error': 'POST request required.'}, status=405)

def chatbot_page(request):
    return render(request, 'nlp_app/chatbot.html')
