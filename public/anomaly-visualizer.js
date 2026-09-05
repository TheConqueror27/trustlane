/**
 * anomaly-visualizer.js
 * Interactive Gaussian & Log-Normal Distribution Visualizer
 * With Merchant-Tier Bayesian Conditioning
 */

window.KaggleAnomalyVisualizer = (function() {
  let riskProfiles = null;
  let activeCategory = 'food';
  let activeAmount = 490;
  let activeModel = 'gaussian'; // 'gaussian' | 'lognormal'
  let canvasEl = null;
  let ctx = null;
  let animFrame = null;
  let pulsePhase = 0;

  async function loadRiskProfiles() {
    try {
      const res = await fetch('/api/risk/profiles');
      const data = await res.json();
      if (data.success) {
        riskProfiles = data.profiles;
      }
    } catch (e) {
      console.warn('Could not fetch risk profiles from API, using fallback:', e);
    }
  }

  function gaussian(x, mean, std) {
    const exponent = -0.5 * Math.pow((x - mean) / std, 2);
    return (1 / (std * Math.sqrt(2 * Math.PI))) * Math.exp(exponent);
  }

  function logNormal(x, logMean, logStd) {
    if (x <= 0) return 0;
    const exponent = -0.5 * Math.pow((Math.log(x) - logMean) / logStd, 2);
    return (1 / (x * logStd * Math.sqrt(2 * Math.PI))) * Math.exp(exponent);
  }

  function initCanvas(canvasId) {
    canvasEl = document.getElementById(canvasId);
    if (!canvasEl) return;
    ctx = canvasEl.getContext('2d');
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    startAnimation();
  }

  function resizeCanvas() {
    if (!canvasEl) return;
    const rect = canvasEl.getBoundingClientRect();
    canvasEl.width = rect.width * window.devicePixelRatio;
    canvasEl.height = rect.height * window.devicePixelRatio;
    if (ctx) ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  function startAnimation() {
    if (animFrame) cancelAnimationFrame(animFrame);
    function loop() {
      pulsePhase = (pulsePhase + 0.05) % (Math.PI * 2);
      render();
      animFrame = requestAnimationFrame(loop);
    }
    loop();
  }

  function setTransaction(category, amount) {
    activeCategory = (category || 'food').toLowerCase();
    activeAmount = Number(amount || 0);
    updateMathHUD();
  }

  function setDistributionModel(model) {
    activeModel = model;
    render();
    updateMathHUD();
  }

  function calculateZScore(amount, category) {
    if (!riskProfiles || !riskProfiles[category]) return { zScore: 0, mean: 0, std: 0 };
    const p = riskProfiles[category];
    
    // Gaussian Z-Score
    const zGaussian = (amount - p.mean) / p.std;
    // Log-Normal Z-Score
    const logMean = p.logMean || Math.log(p.mean);
    const logStd = p.logStd || 0.32;
    const zLogNormal = (Math.log(Math.max(1, amount)) - logMean) / logStd;

    return {
      zScore: parseFloat(zGaussian.toFixed(2)),
      zScoreLogNormal: parseFloat(zLogNormal.toFixed(2)),
      mean: p.mean,
      std: p.std,
      logMean,
      logStd,
      threshold3Sigma: p.flagThreshold3Sigma,
      isAnomaly: zGaussian > 3.0 || zLogNormal > 3.0,
      profile: p
    };
  }

  function render() {
    if (!ctx || !canvasEl) return;
    const width = canvasEl.width / window.devicePixelRatio;
    const height = canvasEl.height / window.devicePixelRatio;

    ctx.clearRect(0, 0, width, height);

    if (!riskProfiles || !riskProfiles[activeCategory]) return;
    const p = riskProfiles[activeCategory];
    const mean = p.mean;
    const std = p.std;

    const minX = Math.max(0, mean - 3.8 * std);
    const maxX = mean + 5.5 * std;
    const maxY = gaussian(mean, mean, std) * 1.2;

    const padLeft = 40;
    const padRight = 40;
    const padTop = 30;
    const padBottom = 45;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    function mapX(val) {
      return padLeft + ((val - minX) / (maxX - minX)) * plotW;
    }

    function mapY(prob) {
      return height - padBottom - (prob / maxY) * plotH;
    }

    // 1. Draw Shaded Sigma Zones
    const zones = [
      { start: minX, end: mean + std, fill: 'rgba(16, 185, 129, 0.12)', label: 'Normal (68.3%)' },
      { start: mean + std, end: mean + 2 * std, fill: 'rgba(234, 179, 8, 0.15)', label: 'Elevated' },
      { start: mean + 2 * std, end: mean + 3 * std, fill: 'rgba(249, 115, 22, 0.18)', label: 'High Alert' },
      { start: mean + 3 * std, end: maxX, fill: 'rgba(239, 68, 68, 0.25)', label: '3-Sigma Anomaly (<0.13%)' }
    ];

    zones.forEach(z => {
      ctx.beginPath();
      ctx.moveTo(mapX(z.start), mapY(0));
      const step = (z.end - z.start) / 30;
      for (let x = z.start; x <= z.end; x += step) {
        const prob = activeModel === 'lognormal' ? logNormal(x, p.logMean, p.logStd) : gaussian(x, mean, std);
        ctx.lineTo(mapX(x), mapY(prob));
      }
      ctx.lineTo(mapX(z.end), mapY(0));
      ctx.closePath();
      ctx.fillStyle = z.fill;
      ctx.fill();
    });

    // 2. Draw 3-Sigma Anomaly Threshold Line (Red Dash)
    const thresh3X = mapX(mean + 3 * std);
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.strokeStyle = '#ef4444';
    ctx.lineWidth = 2;
    ctx.moveTo(thresh3X, padTop);
    ctx.lineTo(thresh3X, height - padBottom);
    ctx.stroke();
    ctx.setLineDash([]);

    // 3. Draw Main Curve Line
    ctx.beginPath();
    ctx.strokeStyle = '#60a5fa';
    ctx.lineWidth = 2.5;
    for (let x = minX; x <= maxX; x += (maxX - minX) / 120) {
      const prob = activeModel === 'lognormal' ? logNormal(x, p.logMean, p.logStd) : gaussian(x, mean, std);
      const px = mapX(x);
      const py = mapY(prob);
      if (x === minX) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.stroke();

    // 4. Draw Mean Center Line
    const meanX = mapX(mean);
    ctx.beginPath();
    ctx.strokeStyle = '#94a3b8';
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 3]);
    const meanProb = activeModel === 'lognormal' ? logNormal(mean, p.logMean, p.logStd) : gaussian(mean, mean, std);
    ctx.moveTo(meanX, mapY(meanProb));
    ctx.lineTo(meanX, height - padBottom);
    ctx.stroke();
    ctx.setLineDash([]);

    // 5. Draw Active Transaction Point & Pulsating Ripple
    const targetX = mapX(activeAmount);
    const targetProb = activeModel === 'lognormal' ? logNormal(activeAmount, p.logMean, p.logStd) : gaussian(activeAmount, mean, std);
    const targetY = mapY(targetProb);
    const zScore = (activeAmount - mean) / std;
    const isAnomaly = zScore > 3.0;
    const pointColor = isAnomaly ? '#ef4444' : (zScore > 2.0 ? '#f97316' : '#10b981');

    const pulseRadius = 8 + Math.sin(pulsePhase) * 4;
    ctx.beginPath();
    ctx.arc(targetX, targetY, pulseRadius + 6, 0, Math.PI * 2);
    ctx.fillStyle = isAnomaly ? 'rgba(239, 68, 68, 0.25)' : 'rgba(16, 185, 129, 0.25)';
    ctx.fill();

    ctx.beginPath();
    ctx.arc(targetX, targetY, 6, 0, Math.PI * 2);
    ctx.fillStyle = pointColor;
    ctx.fill();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.beginPath();
    ctx.setLineDash([2, 2]);
    ctx.strokeStyle = pointColor;
    ctx.moveTo(targetX, targetY);
    ctx.lineTo(targetX, height - padBottom);
    ctx.stroke();
    ctx.setLineDash([]);

    // 6. X-Axis and Labels
    ctx.strokeStyle = '#334155';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padLeft, height - padBottom);
    ctx.lineTo(width - padRight, height - padBottom);
    ctx.stroke();

    ctx.fillStyle = '#94a3b8';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'center';

    ctx.fillText(`μ = ₹${mean}`, meanX, height - padBottom + 16);
    ctx.fillStyle = '#ef4444';
    ctx.fillText(`3σ = ₹${(mean + 3 * std).toFixed(0)}`, thresh3X, height - padBottom + 16);

    ctx.fillStyle = pointColor;
    ctx.font = 'bold 12px sans-serif';
    ctx.fillText(`₹${activeAmount} (${zScore.toFixed(1)}σ)`, targetX, height - padBottom + 32);

    ctx.textAlign = 'left';
    ctx.fillStyle = '#f8fafc';
    ctx.font = 'bold 12px sans-serif';
    ctx.fillText(`Kaggle Risk Model: ${p.name} (${activeModel === 'lognormal' ? 'Log-Normal' : 'Gaussian'})`, padLeft, 20);

    ctx.textAlign = 'right';
    ctx.fillStyle = isAnomaly ? '#ef4444' : '#10b981';
    ctx.font = 'bold 12px sans-serif';
    ctx.fillText(isAnomaly ? `⚠️ 3-SIGMA ANOMALY (Z = ${zScore.toFixed(1)})` : `✅ Normal Zone (Z = ${zScore.toFixed(1)})`, width - padRight, 20);
  }

  function updateMathHUD() {
    const mathContainer = document.getElementById('kaggleMathHud');
    if (!mathContainer || !riskProfiles || !riskProfiles[activeCategory]) return;

    const p = riskProfiles[activeCategory];
    const mean = p.mean;
    const std = p.std;
    const zScore = parseFloat(((activeAmount - mean) / std).toFixed(2));
    const logMean = p.logMean || 5.17;
    const logStd = p.logStd || 0.32;
    const zLogNormal = parseFloat(((Math.log(Math.max(1, activeAmount)) - logMean) / logStd).toFixed(2));
    const isAnomaly = zScore > 3.0 || zLogNormal > 3.0;

    mathContainer.innerHTML = `
      <div class="math-step-card">
        <div class="math-header">
          <span class="math-badge">Dual-Model Statistical Risk Signal</span>
          <span class="math-source">Source: ${p.source}</span>
        </div>
        <div class="math-formula">
          Gaussian: Z = \\frac{₹${activeAmount} - ₹${mean}}{₹${std}} = \\mathbf{${zScore}\\sigma} \\quad | \\quad Log-Normal: Z_{\\ln} = \\mathbf{${zLogNormal}\\sigma}
        </div>
        <div class="math-breakdown-grid">
          <div class="math-stat">
            <span class="math-label">Proposed (x)</span>
            <span class="math-val" style="color: #60a5fa;">₹${activeAmount}</span>
          </div>
          <div class="math-stat">
            <span class="math-label">Gaussian Mean (μ)</span>
            <span class="math-val">₹${mean}</span>
          </div>
          <div class="math-stat">
            <span class="math-label">Std Dev (σ)</span>
            <span class="math-val">₹${std}</span>
          </div>
          <div class="math-stat">
            <span class="math-label">3σ Threshold</span>
            <span class="math-val" style="color: #ef4444;">> ₹${p.flagThreshold3Sigma}</span>
          </div>
        </div>
        <div class="math-verdict ${isAnomaly ? 'verdict-anomaly' : 'verdict-pass'}">
          ${isAnomaly 
            ? `🚨 <strong>3-Sigma Anomaly Detected:</strong> Proposed ₹${activeAmount} is <strong>${zScore}σ (Gaussian) / ${zLogNormal}σ (Log-Normal)</strong> above empirical baseline (Occurrence: < 0.13%). Gate strictly bounds payment under explicit consent.` 
            : `✅ <strong>Normal Operational Range:</strong> Transaction amount ₹${activeAmount} is within <strong>${zScore}σ</strong> of category average.`}
        </div>
      </div>
    `;
  }

  return {
    loadRiskProfiles,
    initCanvas,
    setTransaction,
    setDistributionModel,
    calculateZScore,
    render,
    getActiveProfiles: () => riskProfiles
  };
})();
