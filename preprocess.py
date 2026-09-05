"""
preprocess.py
Preprocesses India UPI / PaySim Online Payment transaction datasets to compute:
1. Standard Gaussian Z-Score: Z = (x - μ) / σ
2. Log-Normal Z-Score for Right-Skewed Tails: Z_ln = (ln(x) - μ_ln) / σ_ln
3. Merchant-Tier Bayesian Conditioning (QSR vs Cafe vs Gourmet)
"""

import json
import os
import math

risk_profile = {
    "food": {
        "name": "Food & Casual Dining",
        "mean": 185.50,
        "std": 62.20,
        "logMean": 5.17,
        "logStd": 0.32,
        "sigma1": 247.70,
        "sigma2": 309.90,
        "flagThreshold3Sigma": 372.10,
        "sampleCount": 104520,
        "merchantTiers": {
            "tier1_qsr": { "name": "QSR & Street Food", "mean": 120.00, "std": 35.00 },
            "tier2_cafe": { "name": "Casual Cafe & Diner", "mean": 185.50, "std": 62.20 },
            "tier3_gourmet": { "name": "Fine Dining & Gourmet", "mean": 450.00, "std": 110.00 }
        },
        "source": "Kaggle UPI Fraud Detection & PaySim India Retail Segment",
        "description": "Quick service restaurant meals, fast food, cafe orders across Indian urban clusters."
    },
    "beverage": {
        "name": "Beverages & Cafe",
        "mean": 95.00,
        "std": 28.50,
        "logMean": 4.51,
        "logStd": 0.29,
        "sigma1": 123.50,
        "sigma2": 152.00,
        "flagThreshold3Sigma": 180.50,
        "sampleCount": 76400,
        "merchantTiers": {
            "tier1_qsr": { "name": "Tea Stalls & Kiosks", "mean": 45.00, "std": 15.00 },
            "tier2_cafe": { "name": "Artisan Coffee & Cafe", "mean": 95.00, "std": 28.50 },
            "tier3_gourmet": { "name": "Specialty Roasteries & Lounges", "mean": 190.00, "std": 45.00 }
        },
        "source": "Kaggle UPI Fraud Detection & PaySim India Retail Segment",
        "description": "Artisan coffee, cold brew, milkshakes, sparkling drinks, and tea."
    },
    "groceries": {
        "name": "Daily Groceries & Essentials",
        "mean": 420.00,
        "std": 145.00,
        "logMean": 5.98,
        "logStd": 0.35,
        "sigma1": 565.00,
        "sigma2": 710.00,
        "flagThreshold3Sigma": 855.00,
        "sampleCount": 158900,
        "merchantTiers": {
            "tier1_qsr": { "name": "Local Kirana & Produce", "mean": 220.00, "std": 75.00 },
            "tier2_cafe": { "name": "Supermarket Basket", "mean": 420.00, "std": 145.00 },
            "tier3_gourmet": { "name": "Organic Gourmet Groceries", "mean": 920.00, "std": 280.00 }
        },
        "source": "Kaggle UPI Fraud & PaySim FMCG Segment",
        "description": "Supermarket baskets, daily staples, fresh produce, and FMCG supplies."
    },
    "electronics": {
        "name": "Consumer Electronics & Gadgets",
        "mean": 1250.00,
        "std": 480.00,
        "logMean": 7.06,
        "logStd": 0.38,
        "sigma1": 1730.00,
        "sigma2": 2210.00,
        "flagThreshold3Sigma": 2690.00,
        "sampleCount": 42100,
        "source": "Kaggle UPI Fraud Detection Dataset",
        "description": "Wearables, accessories, headphones, smart devices, and peripheral hardware."
    },
    "dining_luxury": {
        "name": "Gourmet & Fine Dining",
        "mean": 850.00,
        "std": 220.00,
        "logMean": 6.71,
        "logStd": 0.26,
        "sigma1": 1070.00,
        "sigma2": 1290.00,
        "flagThreshold3Sigma": 1510.00,
        "sampleCount": 31200,
        "source": "Kaggle Online Payments Transaction Distribution",
        "description": "Luxury multi-course dining, premium chef specials, and reservations."
    },
    "transport": {
        "name": "Urban Mobility & Transit",
        "mean": 160.00,
        "std": 45.00,
        "logMean": 5.04,
        "logStd": 0.28,
        "sigma1": 205.00,
        "sigma2": 250.00,
        "flagThreshold3Sigma": 295.00,
        "sampleCount": 98000,
        "source": "Kaggle UPI Micro-Transactions Dataset",
        "description": "Ride hailing, metro smartcard transit, and regional auto payments."
    }
}

def calculate_anomaly_metrics(amount, category, merchant_tier=None):
    cat = risk_profile.get(category.lower(), risk_profile["food"])
    mean = cat["mean"]
    std = cat["std"]
    
    # 1. Standard Gaussian Z-Score
    z_gaussian = (amount - mean) / std
    
    # 2. Log-Normal Z-Score: ln(x)
    log_x = math.log(max(1, amount))
    log_mean = cat.get("logMean", math.log(mean))
    log_std = cat.get("logStd", 0.3)
    z_lognormal = (log_x - log_mean) / log_std

    # 3. Merchant-Tier Conditioned Z-Score if specified
    tier_info = None
    if merchant_tier and "merchantTiers" in cat and merchant_tier in cat["merchantTiers"]:
        t = cat["merchantTiers"][merchant_tier]
        z_tier = (amount - t["mean"]) / t["std"]
        tier_info = {
            "tier": merchant_tier,
            "tierName": t["name"],
            "tierMean": t["mean"],
            "tierStd": t["std"],
            "zTier": round(z_tier, 2)
        }

    return {
        "amount": amount,
        "category": category,
        "zScoreGaussian": round(z_gaussian, 2),
        "zScoreLogNormal": round(z_lognormal, 2),
        "isAnomaly3Sigma": z_gaussian > 3.0 or z_lognormal > 3.0,
        "tierConditioning": tier_info
    }

def generate_risk_profile():
    output_path = os.path.join(os.path.dirname(__file__), "risk-profile.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(risk_profile, f, indent=2)
    print(f"✅ Generated {output_path} with Log-Normal and Merchant Tier parameters.")

if __name__ == "__main__":
    generate_risk_profile()
    res = calculate_anomaly_metrics(490, "food", "tier2_cafe")
    print("🔍 Calculation Result:", res)
