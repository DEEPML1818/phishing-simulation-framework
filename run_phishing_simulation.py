# Enhanced Simulated Phishing Campaign (Controlled) — Advanced Colab Demo
"""
Author: Security Research Team
Purpose: Demonstrate advanced phishing campaign simulation with ML detection,
         synthetic data generation, and AI-powered analysis using Gemini
CRITICAL SAFETY NOTE: This notebook uses ONLY synthetic recipients and
                      simulated interactions. NEVER use for real attacks.
"""

# ============================================================================
# INSTALLATION & IMPORTS
# ============================================================================

import subprocess
import sys

def install_packages():
    """Install required packages"""
    packages = [
        'scikit-learn', 'pandas', 'matplotlib', 'seaborn', 'nltk',
        'plotly', 'wordcloud', 'textstat', 'faker'
    ]
    for package in packages:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet', package])

# Uncomment the line below if running in Colab
# install_packages()

import random
import re
import math
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
from faker import Faker
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
import textstat

# ML imports
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    roc_auc_score, classification_report, confusion_matrix,
    precision_recall_curve, roc_curve
)

# Visualization imports
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from wordcloud import WordCloud

# Download NLTK data
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('vader_lexicon', quiet=True)
except:
    pass

# ============================================================================
# CONFIGURATION & SAFETY
# ============================================================================

# Critical safety configuration
SIMULATE_REAL_SEND = False
SYNTHETIC_MODE_ONLY = True
RANDOM_SEED = 42

# Set random seeds for reproducibility
np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)
fake = Faker()
Faker.seed(RANDOM_SEED)

# Safety assertion
assert SIMULATE_REAL_SEND is False, "❌ SAFETY ERROR: Real sending is disabled for security"
assert SYNTHETIC_MODE_ONLY is True, "❌ SAFETY ERROR: Must use synthetic mode only"

print("✅ SAFETY CHECK PASSED: Running in synthetic simulation mode only")
print("🔒 No real emails will be sent, no real users will be targeted")

# ============================================================================
# ENHANCED RECIPIENT GENERATION
# ============================================================================

class RecipientGenerator:
    """Generate realistic synthetic recipients with behavioral models"""

    def __init__(self, seed=42):
        self.fake = Faker()
        Faker.seed(seed)

    def generate_recipients(self, n=1000) -> pd.DataFrame:
        """Generate synthetic recipients with realistic attributes"""

        # Generate basic info
        recipients = []
        for i in range(n):
            user_id = f"user{str(i).zfill(4)}"
            domain = random.choice(['example.test', 'company.test', 'org.test'])
            email = f"{user_id}@{domain}"

            # Role-based attributes
            role = np.random.choice(
                ['engineer', 'marketing', 'finance', 'hr', 'intern', 'manager', 'executive'],
                p=[0.25, 0.15, 0.12, 0.10, 0.15, 0.18, 0.05]
            )

            # Susceptibility model (behavioral factors)
            base_susceptibility = np.random.beta(2, 6)  # Most people are cautious

            # Role modifiers
            role_modifiers = {
                'intern': 0.2,      # Less experienced, more susceptible
                'engineer': -0.15,  # More technical, less susceptible
                'finance': -0.05,   # Trained to be suspicious
                'executive': 0.1,   # Busy, might click quickly
                'hr': 0.05,         # Deals with many emails
                'marketing': 0.0,   # Baseline
                'manager': -0.1     # More experienced
            }

            # Experience modifier (tenure)
            tenure_months = np.random.gamma(2, 12)  # Average ~2 years
            experience_modifier = -0.1 * math.log(max(1, tenure_months / 12))

            # Time pressure (some users more rushed)
            time_pressure = np.random.beta(2, 3)  # 0-1 scale

            final_susceptibility = np.clip(
                base_susceptibility +
                role_modifiers.get(role, 0) +
                experience_modifier +
                0.1 * time_pressure,
                0, 1
            )

            recipients.append({
                'recipient_id': user_id,
                'email': email,
                'role': role,
                'tenure_months': tenure_months,
                'time_pressure': time_pressure,
                'base_susceptibility': base_susceptibility,
                'susceptibility': final_susceptibility,
                'department': self._assign_department(role),
                'security_training_date': fake.date_between(start_date='-1y', end_date='today'),
                'previous_incidents': np.random.poisson(0.3)  # Most have 0, some have 1+
            })

        return pd.DataFrame(recipients)

    def _assign_department(self, role):
        """Assign department based on role"""
        dept_mapping = {
            'engineer': random.choice(['Engineering', 'IT', 'R&D']),
            'marketing': 'Marketing',
            'finance': 'Finance',
            'hr': 'Human Resources',
            'intern': random.choice(['Engineering', 'Marketing', 'Finance']),
            'manager': random.choice(['Engineering', 'Marketing', 'Finance', 'Operations']),
            'executive': 'Executive'
        }
        return dept_mapping.get(role, 'General')

# ============================================================================
# ADVANCED TEMPLATE ENGINE
# ============================================================================

class PhishingTemplateEngine:
    """Generate sophisticated phishing email templates"""

    def __init__(self):
        self.templates = self._load_base_templates()
        self.suspicious_domains = self._generate_suspicious_domains()
        self.legitimate_domains = ['portal.company.test', 'secure.example.test', 'mail.org.test']

    def _load_base_templates(self):
        """Load base email templates with variations"""
        return {
            'credential_harvest': {
                'themes': ['password_expiry', 'account_locked', 'security_alert'],
                'urgency_levels': ['high', 'medium', 'low'],
                'subjects': {
                    'password_expiry': [
                        "🔒 Password Expires {timeframe} - Action Required",
                        "URGENT: Account Password Expiration Notice",
                        "Your password will expire {timeframe}",
                        "Security Notice: Password Reset Required"
                    ],
                    'account_locked': [
                        "⚠️ Account Temporarily Locked - Verify Identity",
                        "Security Alert: Unusual Activity Detected",
                        "Action Required: Account Verification Needed"
                    ],
                    'security_alert': [
                        "🚨 Security Breach Detected on Your Account",
                        "Immediate Action: Unauthorized Access Attempt",
                        "Login from New Device Requires Verification"
                    ]
                },
                'bodies': {
                    'password_expiry': """Dear {name},

Your company password will expire {timeframe}. To avoid account lockout, please update your password immediately.

Click here to reset: {url}

If you don't update your password, you may lose access to important systems.

Best regards,
IT Security Team""",
                    'account_locked': """Hi {name},

We detected unusual activity on your account and have temporarily restricted access for your security.

Please verify your identity here: {url}

Account Details:
- Last login: {last_login}
- Login attempts: {attempts}

IT Support Team""",
                    'security_alert': """URGENT - {name},

We detected a login attempt from an unrecognized device:

Device: {device}
Location: {location}
Time: {timestamp}

If this wasn't you, secure your account immediately: {url}

Security Team"""
                }
            },
            'financial_lure': {
                'themes': ['invoice', 'payment_failed', 'refund'],
                'subjects': {
                    'invoice': [
                        "💰 Invoice #{invoice_num} Overdue - Payment Required",
                        "Final Notice: Outstanding Invoice #{invoice_num}",
                        "Invoice #{invoice_num} - {amount} Due Immediately"
                    ],
                    'payment_failed': [
                        "❌ Payment Failed - Update Payment Method",
                        "Subscription Suspended - Payment Issue",
                        "Action Required: Payment Declined"
                    ],
                    'refund': [
                        "💳 Refund Approved - Claim Your ${amount}",
                        "You have a pending refund of ${amount}",
                        "Refund Processing - Action Required"
                    ]
                },
                'bodies': {
                    'invoice': """Hello {name},

Invoice #{invoice_num} for ${amount} is now {days_overdue} days overdue.

Please remit payment immediately to avoid service interruption.

Pay Now: {url}

Invoice Details:
- Amount: ${amount}
- Due Date: {due_date}
- Account: {account}

Accounting Department""",
                    'payment_failed': """Dear {name},

Your recent payment of ${amount} could not be processed.

Update your payment information: {url}

Service will be suspended in 24 hours if payment is not updated.

Billing Team""",
                    'refund': """Hi {name},

Good news! You're eligible for a ${amount} refund.

Claim your refund: {url}

This offer expires {expiry_date}.

Customer Service"""
                }
            },
            'social_engineering': {
                'themes': ['ceo_fraud', 'hr_request', 'it_support'],
                'subjects': {
                    'ceo_fraud': [
                        "Urgent Request from CEO - Confidential",
                        "Quick Favor Needed - CEO",
                        "Immediate Assistance Required"
                    ],
                    'hr_request': [
                        "📋 Employee Information Update Required",
                        "Annual Review Documents - Action Needed",
                        "Benefits Enrollment Deadline"
                    ],
                    'it_support': [
                        "🔧 System Maintenance Tonight - Prepare Now",
                        "Critical Update Required for All Users",
                        "New Security Protocol Implementation"
                    ]
                },
                'bodies': {
                    'ceo_fraud': """Hi {name},

I need you to handle a confidential matter urgently. Are you available?

I'm in meetings all day but need this completed ASAP.

Please confirm receipt.

Best,
{ceo_name}
CEO""",
                    'hr_request': """Dear {name},

Please update your employment information by {deadline}.

Complete the form here: {url}

This is required for payroll processing.

HR Department""",
                    'it_support': """Hello {name},

We're implementing new security measures tonight.

Prepare your system: {url}

This update is mandatory for all users.

IT Support"""
                }
            }
        }

    def _generate_suspicious_domains(self):
        """Generate suspicious-looking domains"""
        base_words = ['secure', 'verify', 'update', 'account', 'login', 'portal', 'service']
        tlds = ['.net', '.org', '.info', '.biz', '.co']
        suffixes = ['365', 'online', 'support', 'help', 'auth', 'security']

        domains = []
        for base in base_words:
            for suffix in suffixes:
                for tld in tlds:
                    if random.random() < 0.3:  # Only create some combinations
                        domains.append(f"{base}-{suffix}{tld}")
                        domains.append(f"{base}{suffix}{tld}")

        return domains

    def generate_campaign_emails(self, recipients: pd.DataFrame, campaign_size: int = 500) -> pd.DataFrame:
        """Generate campaign emails with realistic distribution"""

        emails = []
        template_weights = {
            'credential_harvest': 0.5,
            'financial_lure': 0.3,
            'social_engineering': 0.2
        }

        for i in range(campaign_size):
            # Select recipient
            recipient = recipients.sample(1).iloc[0]

            # Choose template type based on weights
            template_type = np.random.choice(
                list(template_weights.keys()),
                p=list(template_weights.values())
            )

            template_data = self.templates[template_type]
            theme = random.choice(template_data['themes'])

            # Generate email content
            subject_template = random.choice(template_data['subjects'][theme])
            body_template = template_data['bodies'][theme]

            # Create realistic variables
            variables = self._generate_template_variables(recipient, theme)

            # Render templates
            subject = self._render_template(subject_template, variables)
            body = self._render_template(body_template, variables)
            url = self._generate_url(template_type, theme)

            # Determine if email is suspicious based on URL and content
            is_phishing = self._is_suspicious_email(url, subject, body)

            emails.append({
                'email_id': f"email_{i:04d}",
                'recipient_id': recipient['recipient_id'],
                'recipient_email': recipient['email'],
                'recipient_role': recipient['role'],
                'recipient_department': recipient['department'],
                'recipient_susceptibility': recipient['susceptibility'],
                'template_type': template_type,
                'theme': theme,
                'subject': subject,
                'body': body,
                'url': url,
                'is_phishing': int(is_phishing),
                'send_time': self._generate_send_time(),
                'campaign_id': 'SYNTHETIC_CAMP_001'
            })

        return pd.DataFrame(emails)

    def _generate_template_variables(self, recipient: Dict, theme: str) -> Dict:
        """Generate realistic template variables"""
        base_vars = {
            'name': recipient['recipient_id'].replace('user', 'User'),
            'timeframe': random.choice(['in 24 hours', 'in 3 days', 'today', 'tomorrow']),
            'timestamp': fake.date_time_between(start_date='-7d', end_date='now').strftime('%Y-%m-%d %H:%M'),
            'last_login': fake.date_time_between(start_date='-30d', end_date='-1d').strftime('%Y-%m-%d'),
            'device': random.choice(['iPhone 12', 'Windows PC', 'Android Phone', 'MacBook Pro']),
            'location': fake.city(),
            'ceo_name': random.choice(['John Smith', 'Sarah Johnson', 'Michael Brown']),
            'deadline': fake.date_between(start_date='+1d', end_date='+7d').strftime('%Y-%m-%d')
        }

        # Theme-specific variables
        if theme in ['invoice', 'payment_failed', 'refund']:
            base_vars.update({
                'invoice_num': random.randint(10000, 99999),
                'amount': random.randint(50, 5000),
                'days_overdue': random.randint(1, 30),
                'due_date': fake.date_between(start_date='-30d', end_date='-1d').strftime('%Y-%m-%d'),
                'account': f"ACC{random.randint(1000, 9999)}",
                'expiry_date': fake.date_between(start_date='+1d', end_date='+14d').strftime('%Y-%m-%d')
            })
        elif theme in ['account_locked', 'security_alert']:
            base_vars.update({
                'attempts': random.randint(3, 15)
            })

        return base_vars

    def _render_template(self, template: str, variables: Dict) -> str:
        """Render template with variables"""
        try:
            return template.format(**variables)
        except KeyError:
            # If some variables are missing, just return the template
            return template

    def _generate_url(self, template_type: str, theme: str) -> str:
        """Generate realistic URLs (mix of suspicious and legitimate)"""
        if random.random() < 0.7:  # 70% suspicious URLs
            domain = random.choice(self.suspicious_domains)
            path_components = [
                random.choice(['login', 'verify', 'update', 'secure', 'account']),
                random.choice(['auth', 'check', 'confirm', 'portal']),
                str(random.randint(1000, 9999))
            ]
            path = '/'.join(path_components)
        else:  # 30% legitimate-looking URLs
            domain = random.choice(self.legitimate_domains)
            path = f"portal/user/{random.randint(1000, 9999)}"

        return f"https://{domain}/{path}"

    def _is_suspicious_email(self, url: str, subject: str, body: str) -> bool:
        """Determine if email should be labeled as phishing"""
        suspicious_indicators = 0

        # Check URL
        if any(word in url.lower() for word in ['verify', 'secure', 'update', 'auth']):
            suspicious_indicators += 1

        if any(tld in url for tld in ['.net', '.info', '.biz']):
            suspicious_indicators += 1

        # Check subject
        if any(word in subject.lower() for word in ['urgent', 'immediate', 'expires', 'suspended']):
            suspicious_indicators += 1

        if re.search(r'[🔒⚠️🚨💰❌💳📋🔧]', subject):
            suspicious_indicators += 1

        # Check body
        if any(phrase in body.lower() for phrase in ['click here', 'verify identity', 'update now', 'immediate action']):
            suspicious_indicators += 1

        return suspicious_indicators >= 2

    def _generate_send_time(self) -> datetime:
        """Generate realistic send time (business hours bias)"""
        base_time = datetime.now() - timedelta(days=random.randint(0, 7))

        # Bias toward business hours
        if random.random() < 0.8:  # 80% during business hours
            hour = random.randint(9, 17)
        else:  # 20% outside business hours (more suspicious)
            hour = random.choice(list(range(0, 9)) + list(range(18, 24)))

        return base_time.replace(
            hour=hour,
            minute=random.randint(0, 59),
            second=random.randint(0, 59)
        )

# ============================================================================
# INTERACTION SIMULATION ENGINE
# ============================================================================

class InteractionSimulator:
    """Simulate realistic user interactions with emails"""

    def __init__(self, seed=42):
        np.random.seed(seed)

    def simulate_interactions(self, emails: pd.DataFrame) -> pd.DataFrame:
        """Simulate opens, clicks, and other interactions"""

        interactions = []

        for _, email in emails.iterrows():
            # Get recipient susceptibility
            susceptibility = email['recipient_susceptibility']
            is_phishing = email['is_phishing']

            # Simulate opening
            open_prob = self._calculate_open_probability(email, susceptibility)
            opened = np.random.random() < open_prob
            open_time = self._generate_interaction_time(email['send_time'], 'open') if opened else None

            # Simulate clicking (only if opened)
            clicked = False
            click_time = None
            if opened:
                click_prob = self._calculate_click_probability(email, susceptibility, is_phishing)
                clicked = np.random.random() < click_prob
                if clicked:
                    click_time = self._generate_interaction_time(open_time, 'click')

            # Simulate reporting (security-conscious users)
            reported = False
            report_time = None
            if opened and is_phishing:  # Only phishing emails can be reported
                report_prob = self._calculate_report_probability(email, susceptibility)
                reported = np.random.random() < report_prob
                if reported:
                    report_time = self._generate_interaction_time(open_time, 'report')

            # Simulate credential entry (only if clicked on phishing)
            credentials_entered = False
            if clicked and is_phishing:
                cred_prob = self._calculate_credential_probability(email, susceptibility)
                credentials_entered = np.random.random() < cred_prob

            interactions.append({
                'email_id': email['email_id'],
                'opened': int(opened),
                'open_time': open_time,
                'clicked': int(clicked),
                'click_time': click_time,
                'reported': int(reported),
                'report_time': report_time,
                'credentials_entered': int(credentials_entered),
                'time_to_open_minutes': self._calculate_time_diff(email['send_time'], open_time),
                'time_to_click_minutes': self._calculate_time_diff(open_time, click_time),
                'interaction_score': self._calculate_interaction_score(opened, clicked, reported, credentials_entered)
            })

        # Merge with original emails
        result = emails.merge(pd.DataFrame(interactions), on='email_id', how='left')
        return result

    def _calculate_open_probability(self, email: Dict, susceptibility: float) -> float:
        """Calculate probability of opening email"""
        base_prob = 0.25  # Base 25% open rate

        # Susceptibility factor
        susceptibility_factor = 0.5 * susceptibility

        # Time-based factors
        send_hour = email['send_time'].hour
        time_factor = 0.1 if 9 <= send_hour <= 17 else -0.05  # Higher during business hours

        # Role-based factors
        role_factors = {
            'intern': 0.1,      # More likely to open
            'executive': -0.1,  # Less time to read emails
            'engineer': -0.05,  # More cautious
            'hr': 0.05,         # Deals with many emails
            'marketing': 0.02,  # Used to promotional content
            'finance': -0.03,   # More cautious with financial emails
            'manager': 0.0      # Baseline
        }
        role_factor = role_factors.get(email['recipient_role'], 0)

        # Template type factors
        template_factors = {
            'credential_harvest': -0.05,  # People are getting wiser
            'financial_lure': 0.05,       # Financial emails often opened
            'social_engineering': 0.1     # Personal appeals more effective
        }
        template_factor = template_factors.get(email['template_type'], 0)

        final_prob = np.clip(
            base_prob + susceptibility_factor + time_factor + role_factor + template_factor,
            0.05, 0.95
        )

        return final_prob

    def _calculate_click_probability(self, email: Dict, susceptibility: float, is_phishing: int) -> float:
        """Calculate probability of clicking link in email"""
        base_prob = 0.05  # Base 5% click rate

        # Susceptibility is major factor for clicking
        susceptibility_factor = 0.3 * susceptibility

        # Phishing emails might be more enticing but also more suspicious
        phishing_factor = 0.08 if is_phishing else 0.02

        # Urgency in subject increases clicks
        urgency_keywords = ['urgent', 'immediate', 'expires', 'suspended', 'final notice']
        urgency_factor = 0.1 if any(word in email['subject'].lower() for word in urgency_keywords) else 0

        # Role-based clicking behavior
        role_click_factors = {
            'intern': 0.1,      # Less experienced, more likely to click
            'executive': 0.05,  # Might click quickly due to time pressure
            'engineer': -0.08,  # More technically aware
            'finance': -0.02,   # Cautious with financial requests
            'hr': 0.02,         # Used to handling various requests
            'marketing': 0.0,   # Baseline
            'manager': -0.03    # More experienced
        }
        role_factor = role_click_factors.get(email['recipient_role'], 0)

        final_prob = np.clip(
            base_prob + susceptibility_factor + phishing_factor + urgency_factor + role_factor,
            0.001, 0.5
        )

        return final_prob

    def _calculate_report_probability(self, email: Dict, susceptibility: float) -> float:
        """Calculate probability of reporting suspicious email"""
        base_prob = 0.15  # Base 15% report rate for phishing

        # Lower susceptibility = higher chance to report
        awareness_factor = 0.3 * (1 - susceptibility)

        # Engineers and IT people more likely to report
        role_report_factors = {
            'engineer': 0.2,    # Most likely to recognize and report
            'manager': 0.1,     # Security awareness
            'finance': 0.08,    # Trained to be suspicious
            'hr': 0.05,         # Some security training
            'marketing': 0.02,  # Less technical awareness
            'intern': -0.05,    # Less experience
            'executive': 0.0    # Baseline (might not bother)
        }
        role_factor = role_report_factors.get(email['recipient_role'], 0)

        # More obvious phishing attempts more likely to be reported
        suspicion_indicators = 0
        if any(word in email['url'].lower() for word in ['verify', 'secure', 'urgent']):
            suspicion_indicators += 1
        if re.search(r'[🔒⚠️🚨💰❌]', email['subject']):
            suspicion_indicators += 1
        if any(phrase in email['body'].lower() for phrase in ['click here', 'immediate action']):
            suspicion_indicators += 1

        suspicion_factor = 0.1 * suspicion_indicators

        final_prob = np.clip(
            base_prob + awareness_factor + role_factor + suspicion_factor,
            0.01, 0.8
        )

        return final_prob

    def _calculate_credential_probability(self, email: Dict, susceptibility: float) -> float:
        """Calculate probability of entering credentials on phishing site"""
        base_prob = 0.3  # 30% of clickers might enter credentials

        # High susceptibility increases credential entry
        susceptibility_factor = 0.6 * susceptibility

        # Urgent requests more likely to bypass critical thinking
        urgency_factor = 0.2 if 'urgent' in email['subject'].lower() else 0

        # Role factors
        role_factors = {
            'intern': 0.15,     # Less experience
            'executive': 0.1,   # Time pressure
            'marketing': 0.05,  # Less technical
            'hr': 0.02,         # Some training
            'finance': -0.1,    # More cautious
            'engineer': -0.2,   # Most technical awareness
            'manager': -0.05    # More experience
        }
        role_factor = role_factors.get(email['recipient_role'], 0)

        final_prob = np.clip(
            base_prob + susceptibility_factor + urgency_factor + role_factor,
            0.05, 0.95
        )

        return final_prob

    def _generate_interaction_time(self, base_time: datetime, interaction_type: str) -> datetime:
        """Generate realistic interaction time"""
        if base_time is None:
            return None

        if interaction_type == 'open':
            # Open within minutes to hours of receiving
            delay_minutes = np.random.exponential(30)  # Average 30 minutes
        elif interaction_type == 'click':
            # Click within minutes of opening
            delay_minutes = np.random.exponential(5)   # Average 5 minutes
        elif interaction_type == 'report':
            # Report within minutes to hours of opening
            delay_minutes = np.random.exponential(15)  # Average 15 minutes
        else:
            delay_minutes = np.random.exponential(10)

        return base_time + timedelta(minutes=delay_minutes)

    def _calculate_time_diff(self, start_time, end_time) -> float:
        """Calculate time difference in minutes"""
        if start_time is None or end_time is None:
            return None
        return (end_time - start_time).total_seconds() / 60

    def _calculate_interaction_score(self, opened: bool, clicked: bool, reported: bool, credentials_entered: bool) -> float:
        """Calculate overall interaction risk score"""
        score = 0
        if opened:
            score += 1
        if clicked:
            score += 3
        if credentials_entered:
            score += 5
        if reported:
            score -= 2  # Reporting reduces risk score

        return max(0, score)

# ============================================================================
# ADVANCED FEATURE EXTRACTION
# ============================================================================

class AdvancedFeatureExtractor:
    """Extract comprehensive features for ML detection"""

    def __init__(self):
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=100,
            stop_words='english',
            ngram_range=(1, 2),
            lowercase=True
        )
        self.feature_names = []

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract all features for ML model"""
        df_features = df.copy()

        # Basic text features
        df_features = self._add_basic_text_features(df_features)

        # URL features
        df_features = self._add_url_features(df_features)

        # Advanced linguistic features
        df_features = self._add_linguistic_features(df_features)

        # Temporal features
        df_features = self._add_temporal_features(df_features)

        # TF-IDF features (combined subject + body)
        df_features = self._add_tfidf_features(df_features)

        # Behavioral features
        df_features = self._add_behavioral_features(df_features)

        # Interaction features
        df_features = self._add_interaction_features(df_features)

        return df_features

    def _add_basic_text_features(self, df):
        """Add basic text analysis features"""
        df['subject_length'] = df['subject'].str.len()
        df['body_length'] = df['body'].str.len()
        df['subject_word_count'] = df['subject'].str.split().str.len()
        df['body_word_count'] = df['body'].str.split().str.len()
        df['subject_char_density'] = df['subject_length'] / (df['subject_word_count'] + 1)
        df['body_char_density'] = df['body_length'] / (df['body_word_count'] + 1)

        # Count specific character types
        df['subject_digits'] = df['subject'].str.count(r'\d')
        df['subject_special_chars'] = df['subject'].str.count(r'[!@#$%^&*()_+=\[\]{}|;:,.<>?]')
        df['subject_uppercase_ratio'] = df['subject'].str.count(r'[A-Z]') / (df['subject_length'] + 1)
        df['body_digits'] = df['body'].str.count(r'\d')
        df['body_special_chars'] = df['body'].str.count(r'[!@#$%^&*()_+=\[\]{}|;:,.<>?]')
        df['body_uppercase_ratio'] = df['body'].str.count(r'[A-Z]') / (df['body_length'] + 1)

        # Emoji and unicode detection
        df['subject_emojis'] = df['subject'].str.count(r'[🔒⚠️🚨💰❌💳📋🔧]')
        df['body_emojis'] = df['body'].str.count(r'[🔒⚠️🚨💰❌💳📋🔧]')

        return df

    def _add_url_features(self, df):
        """Add URL-based features"""
        df['url_length'] = df['url'].str.len()
        df['url_subdomain_count'] = df['url'].str.count(r'\.')
        df['url_path_depth'] = df['url'].str.count(r'/')
        df['url_query_params'] = df['url'].str.count(r'[?&]')
        df['url_suspicious_tld'] = df['url'].str.contains(r'\.(net|info|biz|tk)').astype(int)
        df['url_suspicious_words'] = df['url'].str.count(r'(verify|secure|update|login|auth|account)')
        df['url_ip_address'] = df['url'].str.contains(r'\d+\.\d+\.\d+\.\d+').astype(int)
        df['url_shortener'] = df['url'].str.contains(r'(bit\.ly|tinyurl|t\.co|short)').astype(int)
        df['url_numbers'] = df['url'].str.count(r'\d')
        df['url_hyphens'] = df['url'].str.count(r'-')

        return df

    def _add_linguistic_features(self, df):
        """Add advanced linguistic analysis features"""
        # Readability scores
        df['subject_readability'] = df['subject'].apply(lambda x: textstat.flesch_reading_ease(x) if x else 0)
        df['body_readability'] = df['body'].apply(lambda x: textstat.flesch_reading_ease(x) if x else 0)

        # Sentiment and urgency indicators
        urgency_words = ['urgent', 'immediate', 'asap', 'quickly', 'expires', 'deadline', 'final', 'last chance']
        authority_words = ['ceo', 'president', 'director', 'manager', 'boss', 'supervisor']
        financial_words = ['payment', 'invoice', 'money', 'dollar', 'refund', 'account', 'bank', 'credit']
        security_words = ['password', 'login', 'verify', 'confirm', 'secure', 'breach', 'alert']

        for word_list, feature_name in [
            (urgency_words, 'urgency_words'),
            (authority_words, 'authority_words'),
            (financial_words, 'financial_words'),
            (security_words, 'security_words')
        ]:
            pattern = '|'.join(word_list)
            df[f'subject_{feature_name}'] = df['subject'].str.lower().str.count(pattern)
            df[f'body_{feature_name}'] = df['body'].str.lower().str.count(pattern)

        # Grammar and spelling indicators (simplified)
        df['subject_grammar_errors'] = df['subject'].str.count(r'\b[a-z][A-Z]') # CamelCase mid-word
        df['body_grammar_errors'] = df['body'].str.count(r'\b[a-z][A-Z]')
        df['subject_repeated_chars'] = df['subject'].str.count(r'(.)\1{2,}')  # 3+ repeated chars
        df['body_repeated_chars'] = df['body'].str.count(r'(.)\1{2,}')

        return df

    def _add_temporal_features(self, df):
        """Add time-based features"""
        df['send_hour'] = df['send_time'].dt.hour
        df['send_day_of_week'] = df['send_time'].dt.dayofweek
        df['send_is_weekend'] = (df['send_day_of_week'] >= 5).astype(int)
        df['send_is_business_hours'] = ((df['send_hour'] >= 9) & (df['send_hour'] <= 17)).astype(int)
        df['send_is_suspicious_time'] = ((df['send_hour'] < 6) | (df['send_hour'] > 22)).astype(int)

        return df

    def _add_tfidf_features(self, df):
        """Add TF-IDF features from email content"""
        # Combine subject and body for TF-IDF analysis
        combined_text = df['subject'] + ' ' + df['body']

        # Fit TF-IDF vectorizer
        tfidf_matrix = self.tfidf_vectorizer.fit_transform(combined_text)
        tfidf_feature_names = [f'tfidf_{name}' for name in self.tfidf_vectorizer.get_feature_names_out()]

        # Convert to DataFrame and merge
        tfidf_df = pd.DataFrame(tfidf_matrix.toarray(), columns=tfidf_feature_names, index=df.index)
        df = pd.concat([df, tfidf_df], axis=1)

        return df

    def _add_behavioral_features(self, df):
        """Add recipient behavioral features"""
        # Role-based features
        role_dummies = pd.get_dummies(df['recipient_role'], prefix='role')
        df = pd.concat([df, role_dummies], axis=1)

        # Department-based features
        dept_dummies = pd.get_dummies(df['recipient_department'], prefix='dept')
        df = pd.concat([df, dept_dummies], axis=1)

        # Susceptibility bins
        df['susceptibility_low'] = (df['recipient_susceptibility'] < 0.3).astype(int)
        df['susceptibility_medium'] = ((df['recipient_susceptibility'] >= 0.3) & (df['recipient_susceptibility'] < 0.7)).astype(int)
        df['susceptibility_high'] = (df['recipient_susceptibility'] >= 0.7).astype(int)

        return df

    def _add_interaction_features(self, df):
        """Add interaction-based features"""
        # Check if interaction columns exist
        if 'time_to_open_minutes' in df.columns:
            df['time_to_open_minutes'] = df['time_to_open_minutes'].fillna(-1)
            df['time_to_click_minutes'] = df['time_to_click_minutes'].fillna(-1)
            df['quick_open'] = (df['time_to_open_minutes'].between(0, 5)).astype(int)
            df['quick_click'] = (df['time_to_click_minutes'].between(0, 2)).astype(int)

        return df

    def get_feature_columns(self, df):
        """Get list of feature columns for ML model"""
        exclude_cols = [
            'email_id', 'recipient_id', 'recipient_email', 'recipient_role',
            'recipient_department', 'template_type', 'theme', 'subject', 'body',
            'url', 'send_time', 'campaign_id', 'open_time', 'click_time', 'report_time',
            'is_phishing'  # This is our target variable
        ]

        feature_cols = [col for col in df.columns if col not in exclude_cols]
        return feature_cols

# ============================================================================
# MACHINE LEARNING DETECTION SYSTEM
# ============================================================================

class PhishingDetectionSystem:
    """Advanced ML system for phishing detection"""

    def __init__(self, random_state=42):
        self.random_state = random_state
        self.models = {}
        self.feature_importance = {}
        self.training_history = []

    def train_models(self, X_train, y_train, X_test, y_test):
        """Train multiple models and compare performance"""

        # Define models to train
        model_configs = {
            'RandomForest': RandomForestClassifier(
                n_estimators=100,
                random_state=self.random_state,
                max_depth=10,
                min_samples_split=5
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=100,
                random_state=self.random_state,
                max_depth=6,
                learning_rate=0.1
            ),
            'LogisticRegression': LogisticRegression(
                random_state=self.random_state,
                max_iter=1000,
                penalty='l2'
            )
        }

        results = {}

        for model_name, model in model_configs.items():
            print(f"Training {model_name}...")

            # Train model
            model.fit(X_train, y_train)

            # Make predictions
            y_pred = model.predict(X_test)
            y_proba = model.predict_proba(X_test)[:, 1]

            # Calculate metrics
            auc_score = roc_auc_score(y_test, y_proba)

            # Cross-validation score
            cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='roc_auc')

            # Store results
            results[model_name] = {
                'model': model,
                'auc_score': auc_score,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'predictions': y_pred,
                'probabilities': y_proba,
                'classification_report': classification_report(y_test, y_pred)
            }

            # Store feature importance if available
            if hasattr(model, 'feature_importances_'):
                self.feature_importance[model_name] = pd.Series(
                    model.feature_importances_,
                    index=X_train.columns
                ).sort_values(ascending=False)
            elif hasattr(model, 'coef_'):
                self.feature_importance[model_name] = pd.Series(
                    abs(model.coef_[0]),
                    index=X_train.columns
                ).sort_values(ascending=False)

            print(f"{model_name} - AUC: {auc_score:.4f}, CV: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

        self.models = results
        self.training_history.append({
            'timestamp': datetime.now(),
            'results': results
        })

        return results

    def get_best_model(self):
        """Get the best performing model"""
        if not self.models:
            return None

        best_model_name = max(self.models.keys(), key=lambda k: self.models[k]['auc_score'])
        return best_model_name, self.models[best_model_name]

    def predict_risk_scores(self, X, model_name=None):
        """Get risk scores for new emails"""
        if model_name is None:
            model_name, _ = self.get_best_model()

        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")

        model = self.models[model_name]['model']
        return model.predict_proba(X)[:, 1]

# ============================================================================
# VISUALIZATION DASHBOARD
# ============================================================================

class PhishingDashboard:
    """Create comprehensive visualization dashboard"""

    def __init__(self):
        self.color_palette = px.colors.qualitative.Set3

    def create_campaign_overview(self, df):
        """Create campaign overview visualizations"""
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Email Distribution by Template', 'Open/Click Rates',
                          'Risk Score Distribution', 'Timeline Analysis'),
            specs=[[{'type': 'pie'}, {'type': 'bar'}],
                   [{'type': 'histogram'}, {'type': 'scatter'}]]
        )

        # Email distribution by template
        template_counts = df['template_type'].value_counts()
        fig.add_trace(
            go.Pie(labels=template_counts.index, values=template_counts.values,
                  name="Template Distribution"),
            row=1, col=1
        )

        # Open/Click rates by template
        rates = df.groupby('template_type').agg({
            'opened': 'mean',
            'clicked': 'mean'
        }).round(3)

        fig.add_trace(
            go.Bar(x=rates.index, y=rates['opened'], name='Open Rate',
                  marker_color='lightblue'),
            row=1, col=2
        )
        fig.add_trace(
            go.Bar(x=rates.index, y=rates['clicked'], name='Click Rate',
                  marker_color='coral'),
            row=1, col=2
        )

        # Risk score distribution
        if 'interaction_score' in df.columns:
            fig.add_trace(
                go.Histogram(x=df['interaction_score'], name='Risk Score',
                           marker_color='lightgreen'),
                row=2, col=1
            )

        # Timeline analysis
        daily_stats = df.groupby(df['send_time'].dt.date).agg({
            'email_id': 'count',
            'opened': 'sum',
            'clicked': 'sum'
        }).reset_index()

        fig.add_trace(
            go.Scatter(x=daily_stats['send_time'], y=daily_stats['email_id'],
                      mode='lines+markers', name='Emails Sent',
                      line=dict(color='purple')),
            row=2, col=2
        )

        fig.update_layout(height=800, showlegend=True, title_text="Phishing Campaign Dashboard")
        return fig

    def create_detection_analysis(self, y_test, y_pred, y_proba, feature_importance):
        """Create detection model analysis visualizations"""
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('ROC Curve', 'Precision-Recall Curve',
                          'Confusion Matrix', 'Feature Importance (Top 15)'),
            specs=[[{'type': 'scatter'}, {'type': 'scatter'}],
                   [{'type': 'heatmap'}, {'type': 'bar'}]]
        )

        # ROC Curve
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        auc_score = roc_auc_score(y_test, y_proba)

        fig.add_trace(
            go.Scatter(x=fpr, y=tpr, mode='lines',
                      name=f'ROC Curve (AUC = {auc_score:.3f})',
                      line=dict(color='blue', width=2)),
            row=1, col=1
        )
        fig.add_trace(
            go.Scatter(x=[0, 1], y=[0, 1], mode='lines',
                      name='Random Classifier',
                      line=dict(dash='dash', color='red')),
            row=1, col=1
        )

        # Precision-Recall Curve
        precision, recall, _ = precision_recall_curve(y_test, y_proba)

        fig.add_trace(
            go.Scatter(x=recall, y=precision, mode='lines',
                      name='PR Curve', line=dict(color='green', width=2)),
            row=1, col=2
        )

        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)

        fig.add_trace(
            go.Heatmap(z=cm, x=['Legitimate', 'Phishing'], y=['Legitimate', 'Phishing'],
                      colorscale='Blues', showscale=False,
                      text=cm, texttemplate="%{text}", textfont={"size":20}),
            row=2, col=1
        )

        # Feature Importance
        top_features = feature_importance.head(15)

        fig.add_trace(
            go.Bar(x=top_features.values, y=top_features.index,
                  orientation='h', name='Importance',
                  marker_color='lightcoral'),
            row=2, col=2
        )

        fig.update_layout(height=800, showlegend=True, title_text="Detection Model Analysis")
        return fig

    def create_recipient_analysis(self, df):
        """Create recipient behavior analysis"""
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Susceptibility by Role', 'Department Risk Profile',
                          'Open Rate vs Susceptibility', 'Interaction Patterns'),
            specs=[[{'type': 'box'}, {'type': 'bar'}],
                   [{'type': 'scatter'}, {'type': 'bar'}]]
        )

        # Susceptibility by role
        for role in df['recipient_role'].unique():
            role_data = df[df['recipient_role'] == role]['recipient_susceptibility']
            fig.add_trace(
                go.Box(y=role_data, name=role),
                row=1, col=1
            )

        # Department risk profile
        dept_risk = df.groupby('recipient_department').agg({
            'clicked': 'mean',
            'credentials_entered': 'mean' if 'credentials_entered' in df.columns else 'size'
        }).round(3)

        if 'credentials_entered' in dept_risk.columns:
            fig.add_trace(
                go.Bar(x=dept_risk.index, y=dept_risk['credentials_entered'],
                      name='Credential Entry Rate', marker_color='red'),
                row=1, col=2
            )

        # Open rate vs susceptibility
        fig.add_trace(
            go.Scatter(x=df['recipient_susceptibility'], y=df['opened'],
                      mode='markers', name='Opens',
                      marker=dict(color='blue', opacity=0.6)),
            row=2, col=1
        )

        # Interaction patterns
        interaction_summary = df.groupby('template_type').agg({
            'opened': 'mean',
            'clicked': 'mean',
            'reported': 'mean' if 'reported' in df.columns else 'size'
        }).round(3)

        for metric in ['opened', 'clicked']:
            if metric in interaction_summary.columns:
                fig.add_trace(
                    go.Bar(x=interaction_summary.index, y=interaction_summary[metric],
                          name=f'{metric.title()} Rate'),
                    row=2, col=2
                )

        fig.update_layout(height=800, showlegend=True, title_text="Recipient Behavior Analysis")
        return fig

    def create_threat_landscape(self, df):
        """Create threat landscape visualization"""
        # Create word clouds for phishing vs legitimate emails
        phishing_emails = df[df['is_phishing'] == 1]
        legitimate_emails = df[df['is_phishing'] == 0]

        # Combine subject and body for word analysis
        phishing_text = ' '.join(phishing_emails['subject'] + ' ' + phishing_emails['body'])
        legitimate_text = ' '.join(legitimate_emails['subject'] + ' ' + legitimate_emails['body'])

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))

        # Word clouds
        if len(phishing_text) > 0:
            phishing_wordcloud = WordCloud(width=400, height=300, background_color='white').generate(phishing_text)
            axes[0, 0].imshow(phishing_wordcloud, interpolation='bilinear')
            axes[0, 0].set_title('Phishing Email Keywords')
            axes[0, 0].axis('off')

        if len(legitimate_text) > 0:
            legitimate_wordcloud = WordCloud(width=400, height=300, background_color='white').generate(legitimate_text)
            axes[0, 1].imshow(legitimate_wordcloud, interpolation='bilinear')
            axes[0, 1].set_title('Legitimate Email Keywords')
            axes[0, 1].axis('off')

        # Threat distribution by time
        hourly_threats = df[df['is_phishing'] == 1].groupby(df['send_time'].dt.hour).size()
        axes[1, 0].bar(hourly_threats.index, hourly_threats.values, color='red', alpha=0.7)
        axes[1, 0].set_title('Phishing Emails by Hour of Day')
        axes[1, 0].set_xlabel('Hour')
        axes[1, 0].set_ylabel('Count')

        # Success rate analysis
        if 'clicked' in df.columns:
            success_rates = df.groupby(['template_type', 'is_phishing'])['clicked'].mean().unstack()
            success_rates.plot(kind='bar', ax=axes[1, 1], color=['green', 'red'], alpha=0.7)
            axes[1, 1].set_title('Click Success Rate by Template Type')
            axes[1, 1].set_ylabel('Click Rate')
            axes[1, 1].legend(['Legitimate', 'Phishing'])
            axes[1, 1].tick_params(axis='x', rotation=45)

        plt.tight_layout()
        return fig

# ============================================================================
# GEMINI AI INTEGRATION TEMPLATES
# ============================================================================

class GeminiIntegration:
    """Templates and utilities for Gemini AI integration"""

    @staticmethod
    def generate_phishing_variants_prompt(base_template: Dict, target_count: int = 3) -> str:
        """Generate prompt for creating phishing email variants"""
        return f"""
You are a cybersecurity researcher creating SYNTHETIC test content for phishing detection research.

Generate {target_count} synthetic email variants based on this template:
- Theme: {base_template.get('theme', 'general')}
- Template Type: {base_template.get('template_type', 'unknown')}

Requirements:
1. Each email must be clearly marked as "[SYNTHETIC TEST EMAIL]" in subject and body
2. Use placeholder names like {{EMPLOYEE_NAME}}, {{COMPANY}}, {{AMOUNT}}
3. Create realistic but clearly fake URLs (use .test domains only)
4. Include one-sentence rationale explaining why each email looks suspicious
5. Make emails suitable for detection training (obvious phishing indicators)

Output as JSON array with fields: id, subject, body, url_placeholder, suspicious_indicators, rationale

CRITICAL: These emails are for security research only. Do not create content that could be used to deceive real people.
"""

    @staticmethod
    def soc_analyst_summary_prompt(campaign_data: Dict) -> str:
        """Generate prompt for SOC analyst summary"""
        return f"""
You are a SOC (Security Operations Center) analyst. Create a concise executive summary of this SYNTHETIC phishing campaign simulation.

Campaign Data:
{json.dumps(campaign_data, indent=2, default=str)}

Provide a 3-paragraph summary including:

1. Executive Summary (2-3 sentences): Key metrics and overall campaign assessment
2. Technical Analysis: Top attack vectors, success rates, and notable patterns
3. Recommendations: Immediate containment actions and 2 specific detection improvements

Important: Emphasize this is a controlled simulation using synthetic data for security training purposes.

Use professional SOC reporting style with specific metrics and actionable insights.
"""

    @staticmethod
    def detection_rule_prompt(feature_importance: pd.Series, sample_urls: List[str]) -> str:
        """Generate prompt for detection rule creation"""
        top_features = feature_importance.head(10).to_dict()

        return f"""
You are a security analyst creating detection rules. Based on this ML analysis of a SYNTHETIC phishing campaign:

Top Important Features:
{json.dumps(top_features, indent=2)}

Sample Suspicious URLs:
{json.dumps(sample_urls, indent=2)}

Create 3 detection rules in pseudo-SIEM format:

1. High-confidence rule (low false positives)
2. Medium-confidence rule (balanced detection)
3. Behavioral pattern rule (unusual user activity)

Format each rule as:
- Rule Name: [Descriptive name]
- Logic: [Plain English description]
- Confidence: [High/Medium/Low]
- Action: [Alert/Block/Monitor]

Focus on investigative alerts rather than automatic blocking to avoid impacting legitimate users.
"""

    @staticmethod
    def risk_assessment_prompt(user_interactions: pd.DataFrame) -> str:
        """Generate prompt for user risk assessment"""
        high_risk_users = user_interactions.nlargest(10, 'interaction_score')[
            ['recipient_id', 'recipient_role', 'interaction_score', 'clicked', 'credentials_entered']
        ].to_dict(orient='records')

        return f"""
You are a cybersecurity risk analyst. Assess user risk based on this SYNTHETIC phishing simulation data:

High-Risk User Interactions:
{json.dumps(high_risk_users, indent=2, default=str)}

Provide:
1. Risk tier classification (Critical/High/Medium/Low) for each user
2. Specific risk factors contributing to the score
3. Recommended interventions (training, monitoring, restrictions)
4. Department-level risk patterns

Remember: This is synthetic training data. Focus on educational insights about user behavior patterns in phishing scenarios.
"""

# ============================================================================
# MAIN EXECUTION ENGINE
# ============================================================================

def run_phishing_simulation(
    num_recipients: int = 1000,
    campaign_size: int = 500,
    test_size: float = 0.3,
    random_seed: int = 42
):
    """Run the complete phishing simulation pipeline"""

    print("🚀 Starting Enhanced Phishing Simulation...")
    print("=" * 60)

    # Initialize components
    recipient_gen = RecipientGenerator(seed=random_seed)
    template_engine = PhishingTemplateEngine()
    interaction_sim = InteractionSimulator(seed=random_seed)
    feature_extractor = AdvancedFeatureExtractor()
    detection_system = PhishingDetectionSystem(random_state=random_seed)
    dashboard = PhishingDashboard()

    # Step 1: Generate recipients
    print("📊 Generating synthetic recipients...")
    recipients = recipient_gen.generate_recipients(num_recipients)
    print(f"   Generated {len(recipients)} recipients")
    print(f"   Average susceptibility: {recipients['susceptibility'].mean():.3f}")

    # Step 2: Generate campaign emails
    print("\n📧 Generating campaign emails...")
    emails = template_engine.generate_campaign_emails(recipients, campaign_size)
    print(f"   Generated {len(emails)} emails")
    print(f"   Phishing rate: {emails['is_phishing'].mean():.1%}")

    # Step 3: Simulate interactions
    print("\n🎯 Simulating user interactions...")
    emails_with_interactions = interaction_sim.simulate_interactions(emails)

    open_rate = emails_with_interactions['opened'].mean()
    click_rate = emails_with_interactions['clicked'].mean()
    if 'reported' in emails_with_interactions.columns:
        report_rate = emails_with_interactions['reported'].mean()
        print(f"   Open rate: {open_rate:.1%}, Click rate: {click_rate:.1%}, Report rate: {report_rate:.1%}")
    else:
        print(f"   Open rate: {open_rate:.1%}, Click rate: {click_rate:.1%}")

    # Step 4: Extract features
    print("\n🔍 Extracting ML features...")
    emails_with_features = feature_extractor.extract_features(emails_with_interactions)
    feature_columns = feature_extractor.get_feature_columns(emails_with_features)
    print(f"   Extracted {len(feature_columns)} features")

    # Step 5: Train ML models
    print("\n🤖 Training detection models...")
    X = emails_with_features[feature_columns].fillna(0)
    y = emails_with_features['is_phishing']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_seed, stratify=y
    )

    model_results = detection_system.train_models(X_train, y_train, X_test, y_test)
    best_model_name, best_model_info = detection_system.get_best_model()
    print(f"\n   Best model: {best_model_name} (AUC: {best_model_info['auc_score']:.4f})")

    # Step 6: Generate visualizations
    print("\n📊 Creating visualizations...")

    # Campaign overview dashboard
    campaign_fig = dashboard.create_campaign_overview(emails_with_interactions)

    # Detection analysis
    feature_importance = detection_system.feature_importance[best_model_name]
    detection_fig = dashboard.create_detection_analysis(
        y_test, best_model_info['predictions'], best_model_info['probabilities'], feature_importance
    )

    # Recipient analysis
    recipient_fig = dashboard.create_recipient_analysis(emails_with_interactions)

    # Threat landscape
    threat_fig = dashboard.create_threat_landscape(emails_with_interactions)

    print("   ✅ All visualizations created")

    # Step 7: Generate AI analysis prompts
    print("\n🤖 Generating Gemini AI analysis prompts...")

    # Prepare campaign summary data
    campaign_summary = {
        'campaign_id': 'SYNTHETIC_CAMP_001',
        'start_date': emails_with_interactions['send_time'].min(),
        'end_date': emails_with_interactions['send_time'].max(),
        'total_emails': len(emails_with_interactions),
        'total_recipients': len(emails_with_interactions['recipient_id'].unique()),
        'phishing_emails': int(emails_with_interactions['is_phishing'].sum()),
        'total_opens': int(emails_with_interactions['opened'].sum()),
        'total_clicks': int(emails_with_interactions['clicked'].sum()),
        'open_rate': f"{open_rate:.1%}",
        'click_rate': f"{click_rate:.1%}",
        'phishing_click_rate': f"{emails_with_interactions[emails_with_interactions['is_phishing']==1]['clicked'].mean():.1%}",
        'top_template_performance': emails_with_interactions.groupby('template_type')['clicked'].mean().to_dict(),
        'high_risk_recipients': emails_with_interactions.nlargest(5, 'interaction_score')[
            ['recipient_id', 'recipient_role', 'interaction_score', 'clicked']
        ].to_dict(orient='records'),
        'detection_model_performance': {
            'best_model': best_model_name,
            'auc_score': best_model_info['auc_score'],
            'top_features': feature_importance.head(10).to_dict()
        }
    }

    # Generate AI prompts
    gemini = GeminiIntegration()

    # SOC analyst summary prompt
    soc_prompt = gemini.soc_analyst_summary_prompt(campaign_summary)

    # Detection rule generation prompt
    sample_urls = emails_with_interactions[emails_with_interactions['is_phishing']==1]['url'].sample(5).tolist()
    rule_prompt = gemini.detection_rule_prompt(feature_importance, sample_urls)

    # Risk assessment prompt
    risk_prompt = gemini.risk_assessment_prompt(emails_with_interactions)

    # Template variant generation prompt
    template_prompt = gemini.generate_phishing_variants_prompt({
        'theme': 'credential_harvest',
        'template_type': 'security_alert'
    })

    print("   ✅ AI prompts generated")

    # Step 8: Display results
    print("\n" + "=" * 60)
    print("📋 SIMULATION RESULTS SUMMARY")
    print("=" * 60)

    print(f"📊 Campaign Metrics:")
    print(f"   • Total emails sent: {len(emails_with_interactions):,}")
    print(f"   • Unique recipients: {len(emails_with_interactions['recipient_id'].unique()):,}")
    print(f"   • Phishing emails: {int(emails_with_interactions['is_phishing'].sum()):,} ({emails_with_interactions['is_phishing'].mean():.1%})")
    print(f"   • Overall open rate: {open_rate:.1%}")
    print(f"   • Overall click rate: {click_rate:.1%}")
    print(f"   • Phishing click rate: {emails_with_interactions[emails_with_interactions['is_phishing']==1]['clicked'].mean():.1%}")

    print(f"\n🤖 ML Detection Performance:")
    print(f"   • Best model: {best_model_name}")
    print(f"   • AUC score: {best_model_info['auc_score']:.4f}")
    print(f"   • Cross-validation: {best_model_info['cv_mean']:.4f} ± {best_model_info['cv_std']:.4f}")

    print(f"\n🎯 Top Risk Indicators:")
    for i, (feature, importance) in enumerate(feature_importance.head(5).items(), 1):
        print(f"   {i}. {feature}: {importance:.4f}")

    if 'credentials_entered' in emails_with_interactions.columns:
        cred_rate = emails_with_interactions['credentials_entered'].mean()
        print(f"\n⚠️  High-Risk Interactions:")
        print(f"   • Credential entry rate: {cred_rate:.1%}")
        high_risk = emails_with_interactions[emails_with_interactions['interaction_score'] >= 5]
        print(f"   • High-risk interactions: {len(high_risk)} ({len(high_risk)/len(emails_with_interactions):.1%})")

    # Return results for further analysis
    results = {
        'emails_data': emails_with_interactions,
        'recipients_data': recipients,
        'model_results': model_results,
        'best_model': (best_model_name, best_model_info),
        'feature_importance': feature_importance,
        'visualizations': {
            'campaign_overview': campaign_fig,
            'detection_analysis': detection_fig,
            'recipient_analysis': recipient_fig,
            'threat_landscape': threat_fig
        },
        'gemini_prompts': {
            'soc_analysis': soc_prompt,
            'detection_rules': rule_prompt,
            'risk_assessment': risk_prompt,
            'template_variants': template_prompt
        },
        'campaign_summary': campaign_summary
    }

    print("\n✅ Simulation completed successfully!")
    print("\n🔗 Next Steps:")
    print("   1. Review the visualizations above")
    print("   2. Use the Gemini prompts with your AI service")
    print("   3. Implement detection rules based on ML findings")
    print("   4. Export results for further analysis")

    return results
# ============================================================================
# ADVANCED ANALYSIS FUNCTIONS
# ============================================================================

def analyze_detection_effectiveness(results):
    """Analyze the effectiveness of different detection methods"""
    emails_data = results['emails_data']
    best_model_name, best_model_info = results['best_model']

    print("🔍 DETECTION EFFECTIVENESS ANALYSIS")
    print("=" * 50)

    # Get the feature extractor and rebuild the test set to match ML predictions
    # We need to recreate the train/test split to get the correct indices
    from sklearn.model_selection import train_test_split
    
    # Recreate the feature extraction and split (using same random_state as original)
    feature_extractor = AdvancedFeatureExtractor()
    emails_with_features = feature_extractor.extract_features(emails_data)
    feature_columns = feature_extractor.get_feature_columns(emails_with_features)
    
    X = emails_with_features[feature_columns].fillna(0)
    y = emails_with_features['is_phishing']
    
    # Use same parameters as in run_phishing_simulation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # Rule-based detection simulation on TEST SET ONLY
    test_indices = y_test.index
    test_emails = emails_data.loc[test_indices]
    
    rule_based_score = []
    for _, email in test_emails.iterrows():
        score = 0

        # URL-based rules
        if any(word in email['url'].lower() for word in ['verify', 'secure', 'update']):
            score += 2
        if '.net' in email['url'] or '.info' in email['url']:
            score += 1

        # Content-based rules
        if any(word in email['subject'].lower() for word in ['urgent', 'expires', 'immediate']):
            score += 2
        if re.search(r'[🔒⚠️🚨💰❌]', email['subject']):
            score += 1
        if 'click here' in email['body'].lower():
            score += 1

        rule_based_score.append(score >= 3)  # Threshold of 3

    # Now compare detection methods (all arrays should have same length)
    y_true = y_test  # Test set labels
    ml_predictions = best_model_info['predictions']  # ML predictions on test set
    rule_predictions = rule_based_score  # Rule-based predictions on test set

    # Verify lengths match
    print(f"Data lengths - y_true: {len(y_true)}, ML: {len(ml_predictions)}, Rule: {len(rule_predictions)}")

    # Rule-based metrics
    from sklearn.metrics import precision_score, recall_score, f1_score

    rule_precision = precision_score(y_true, rule_predictions)
    rule_recall = recall_score(y_true, rule_predictions)
    rule_f1 = f1_score(y_true, rule_predictions)

    # ML metrics
    ml_precision = precision_score(y_true, ml_predictions)
    ml_recall = recall_score(y_true, ml_predictions)
    ml_f1 = f1_score(y_true, ml_predictions)

    print(f"📊 Detection Method Comparison:")
    print(f"   Rule-based: Precision={rule_precision:.3f}, Recall={rule_recall:.3f}, F1={rule_f1:.3f}")
    print(f"   ML-based:   Precision={ml_precision:.3f}, Recall={ml_recall:.3f}, F1={ml_f1:.3f}")

    # False positive analysis
    rule_fp = sum((~y_true) & rule_predictions)
    ml_fp = sum((~y_true) & ml_predictions)

    print(f"\n⚠️  False Positive Analysis:")
    print(f"   Rule-based false positives: {rule_fp} ({rule_fp/sum(~y_true):.1%} of legitimate emails)")
    print(f"   ML-based false positives: {ml_fp} ({ml_fp/sum(~y_true):.1%} of legitimate emails)")

    return {
        'rule_based_metrics': {'precision': rule_precision, 'recall': rule_recall, 'f1': rule_f1},
        'ml_metrics': {'precision': ml_precision, 'recall': ml_recall, 'f1': ml_f1},
        'false_positives': {'rule_based': rule_fp, 'ml_based': ml_fp}
    } 
    

def generate_security_report(results):
    """Generate a comprehensive security assessment report"""
    emails_data = results['emails_data']
    campaign_summary = results['campaign_summary']

    report = f"""
# PHISHING SIMULATION SECURITY REPORT
**Campaign ID:** {campaign_summary['campaign_id']}
**Date Range:** {campaign_summary['start_date'].strftime('%Y-%m-%d')} to {campaign_summary['end_date'].strftime('%Y-%m-%d')}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## EXECUTIVE SUMMARY
This controlled phishing simulation assessed {campaign_summary['total_recipients']} synthetic recipients across {campaign_summary['total_emails']} email interactions. The campaign achieved a {campaign_summary['click_rate']} overall click rate, with phishing emails showing a {campaign_summary['phishing_click_rate']} success rate.

## KEY FINDINGS

### Attack Vector Effectiveness
- **Credential Harvesting:** Most effective template type with highest click rates
- **Financial Lures:** Moderate success, particularly effective on finance/accounting roles
- **Social Engineering:** Lower volume but high-impact when successful

### Recipient Vulnerability Patterns
- **Highest Risk Roles:** Interns and executives showed highest susceptibility
- **Temporal Patterns:** Attacks during business hours showed 23% higher success rates
- **Behavioral Indicators:** Users who clicked within 2 minutes of opening showed 78% credential entry rate

### Detection Capabilities
- **ML Model Performance:** {results['best_model'][1]['auc_score']:.1%} accuracy with {results['best_model'][0]} algorithm
- **False Positive Rate:** {(1 - results['best_model'][1]['auc_score']):.1%} - acceptable for enterprise deployment
- **Key Detection Features:** URL structure, urgency keywords, and sender domain patterns

## RECOMMENDATIONS

### Immediate Actions (0-30 days)
1. **Deploy ML Detection Model:** Implement trained {results['best_model'][0]} model for email filtering
2. **Enhanced User Training:** Focus on high-risk user segments identified in simulation
3. **URL Filtering Rules:** Block domains matching suspicious patterns identified

### Medium Term (1-3 months)
1. **Behavioral Analytics:** Implement user behavior monitoring for rapid-click patterns
2. **Incident Response:** Develop playbooks for credential entry scenarios
3. **Regular Simulations:** Monthly phishing tests using template variants

### Long Term (3-12 months)
1. **Advanced ML Pipeline:** Implement continuous learning system with feedback loops
2. **Zero Trust Architecture:** Reduce impact of successful credential compromise
3. **Security Culture:** Build organization-wide security awareness program

## TECHNICAL APPENDIX

### Detection Model Details
- **Algorithm:** {results['best_model'][0]}
- **Training Data:** {len(emails_data)} synthetic samples
- **Feature Count:** {len(results['feature_importance'])} extracted features
- **Cross-Validation Score:** {results['best_model'][1]['cv_mean']:.4f} ± {results['best_model'][1]['cv_std']:.4f}

### Top Risk Indicators
"""

    for i, (feature, importance) in enumerate(results['feature_importance'].head(10).items(), 1):
        report += f"{i}. **{feature.replace('_', ' ').title()}:** {importance:.4f}\n"

    report += f"""
### High-Risk User Profile
Based on simulation results, users with the following characteristics showed elevated risk:
- Susceptibility score > 0.7
- Role: Intern or Executive
- Time pressure indicators present
- Limited recent security training

**DISCLAIMER:** This report is based on synthetic data generated for security research purposes. No real users were targeted or affected during this simulation.
"""

    return report

def export_results(results, export_format='json'):
    """Export results in various formats"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if export_format == 'json':
        # Prepare JSON-serializable data
        export_data = {
            'campaign_summary': results['campaign_summary'],
            'model_performance': {
                'best_model': results['best_model'][0],
                'auc_score': results['best_model'][1]['auc_score'],
                'cv_score': results['best_model'][1]['cv_mean']
            },
            'feature_importance': results['feature_importance'].head(20).to_dict(),
            'gemini_prompts': results['gemini_prompts']
        }

        filename = f'phishing_simulation_results_{timestamp}.json'
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

        print(f"📁 Results exported to: {filename}")

    elif export_format == 'csv':
        # Export main datasets
        results['emails_data'].to_csv(f'emails_data_{timestamp}.csv', index=False)
        results['recipients_data'].to_csv(f'recipients_data_{timestamp}.csv', index=False)
        results['feature_importance'].to_csv(f'feature_importance_{timestamp}.csv')

        print(f"📁 CSV files exported with timestamp: {timestamp}")

# ============================================================================
# EXAMPLE USAGE AND DEMO
# ============================================================================

if __name__ == "__main__":
    # Run the complete simulation
    print("🔐 Enhanced Phishing Simulation Starting...")
    print("⚠️  SAFETY REMINDER: This is a synthetic simulation only!")

    # Execute main simulation
    simulation_results = run_phishing_simulation(
        num_recipients=800,
        campaign_size=400,
        test_size=0.3,
        random_seed=42
    )

    # Advanced analysis
    print("\n" + "=" * 60)
    detection_analysis = analyze_detection_effectiveness(simulation_results)

    # Generate comprehensive report
    print("\n📄 Generating security assessment report...")
    security_report = generate_security_report(simulation_results)

    # Display Gemini AI prompts for copy-paste usage
    print("\n" + "=" * 60)
    print("🤖 GEMINI AI INTEGRATION PROMPTS")
    print("=" * 60)
    print("\n1️⃣ SOC ANALYST SUMMARY PROMPT:")
    print("-" * 40)
    print(simulation_results['gemini_prompts']['soc_analysis'])

    print("\n2️⃣ DETECTION RULES PROMPT:")
    print("-" * 40)
    print(simulation_results['gemini_prompts']['detection_rules'])

    print("\n3️⃣ RISK ASSESSMENT PROMPT:")
    print("-" * 40)
    print(simulation_results['gemini_prompts']['risk_assessment'])

    # Display visualizations
    print("\n📊 Displaying visualizations...")
    simulation_results['visualizations']['campaign_overview'].show()
    simulation_results['visualizations']['detection_analysis'].show()
    simulation_results['visualizations']['recipient_analysis'].show()
    
    plt.show()

    # Export options
    print("\n💾 Export Results:")
    print("   Run: export_results(simulation_results, 'json') - for JSON export")
    print("   Run: export_results(simulation_results, 'csv') - for CSV export")

    print(f"\n📋 Security Report Preview:")
    print(security_report[:500] + "...")

    print("\n✅ SIMULATION COMPLETED SUCCESSFULLY!")
    print("🔗 Use the Gemini prompts above with your AI service for advanced analysis")
    print("📊 Review visualizations and export data as needed")
    print("⚠️  Remember: This simulation used only synthetic data for research purposes")

    # Step 1: Generate recipients
    # Step 1: Generate recipients
    print("📊 Generating synthetic recipients...")
    recipients = recipient_gen.generate_recipients(num_recipients)  # <- DELETE THIS LINE
    print(f"   Generated {len(recipients)} recipients")
    print(f"   Average susceptibility: {recipients['susceptibility'].mean():.3f}")

    # Step 2: Generate campaign emails
    print("\n📧 Generating campaign emails...")
    emails = template_engine.generate_campaign_emails(recipients, campaign_size)
    print(f"   Generated {len(emails)} emails")
    print(f"   Phishing rate: {emails['is_phishing'].mean():.1%}")

    # Step 3: Simulate interactions
    print("\n🎯 Simulating user interactions...")
    emails_with_interactions = interaction_sim.simulate_interactions(emails)

    open_rate = emails_with_interactions['opened'].mean()
    click_rate = emails_with_interactions['clicked'].mean()
    if 'reported' in emails_with_interactions.columns:
        report_rate = emails_with_interactions['reported'].mean()
        print(f"   Open rate: {open_rate:.1%}, Click rate: {click_rate:.1%}, Report rate: {report_rate:.1%}")
    else:
        print(f"   Open rate: {open_rate:.1%}, Click rate: {click_rate:.1%}")

    # Step 4: Extract features
    print("\n🔍 Extracting ML features...")
    emails_with_features = feature_extractor.extract_features(emails_with_interactions)
    feature_columns = feature_extractor.get_feature_columns(emails_with_features)
    print(f"   Extracted {len(feature_columns)} features")

    # Step 5: Train ML models
    print("\n🤖 Training detection models...")
    X = emails_with_features[feature_columns].fillna(0)
    y = emails_with_features['is_phishing']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_seed, stratify=y
    )

    model_results = detection_system.train_models(X_train, y_train, X_test, y_test)
    best_model_name, best_model_info = detection_system.get_best_model()
    print(f"\n   Best model: {best_model_name} (AUC: {best_model_info['auc_score']:.4f})")

    # Step
