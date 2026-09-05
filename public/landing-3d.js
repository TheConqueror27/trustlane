/**
 * landing-3d.js
 * Interactive Three.js Cinematic Scene for TrustLane
 * 
 * Features:
 * - Dynamic 3D Cryptographic Trust Gate (Torus Knot + Hex Shield + Laser Beams)
 * - Converging Neural Payment Particle Stream reacting to cursor movements
 * - Pulsing Holographic Defense Rings
 * - Interactive Mouse-Parallax & Click Wave Ripple Effects
 */

(function () {
  const container = document.getElementById('three-canvas-container');
  if (!container || typeof THREE === 'undefined') return;

  // Scene setup
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x05070d, 0.025);

  const camera = new THREE.PerspectiveCamera(
    60,
    window.innerWidth / window.innerHeight,
    0.1,
    1000
  );
  camera.position.z = 24;

  const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  container.appendChild(renderer.domElement);

  // Groups
  const worldGroup = new THREE.Group();
  scene.add(worldGroup);

  const gateGroup = new THREE.Group();
  worldGroup.add(gateGroup);
  gateGroup.position.set(0, 1.5, 0);

  // 1. Central Holographic Core (Wireframe Torus Knot)
  const knotGeo = new THREE.TorusKnotGeometry(3.5, 0.65, 120, 24, 2, 3);
  const knotMat = new THREE.MeshStandardMaterial({
    color: 0x38bdf8,
    emissive: 0x0284c7,
    emissiveIntensity: 0.85,
    wireframe: true,
    transparent: true,
    opacity: 0.45,
  });
  const knotMesh = new THREE.Mesh(knotGeo, knotMat);
  gateGroup.add(knotMesh);

  // Inner Solid Glow Sphere
  const coreGeo = new THREE.IcosahedronGeometry(1.8, 4);
  const coreMat = new THREE.MeshStandardMaterial({
    color: 0x10b981,
    emissive: 0x059669,
    emissiveIntensity: 1.2,
    roughness: 0.2,
    metalness: 0.8,
    transparent: true,
    opacity: 0.85,
  });
  const coreMesh = new THREE.Mesh(coreGeo, coreMat);
  gateGroup.add(coreMesh);

  // 2. Holographic Concentric Rings (Security Gate Perimeter)
  const ringCount = 3;
  const rings = [];
  for (let i = 0; i < ringCount; i++) {
    const radius = 5.2 + i * 1.8;
    const ringGeo = new THREE.RingGeometry(radius, radius + 0.08, 64);
    const ringMat = new THREE.MeshBasicMaterial({
      color: i % 2 === 0 ? 0x38bdf8 : 0x2dd4bf,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.5 - i * 0.1,
    });
    const ring = new THREE.Mesh(ringGeo, ringMat);
    ring.rotation.x = Math.PI / 2;
    gateGroup.add(ring);
    rings.push({
      mesh: ring,
      speedX: (i + 1) * 0.005 * (i % 2 === 0 ? 1 : -1),
      speedY: (i + 1) * 0.007 * (i % 2 === 0 ? -1 : 1),
    });
  }

  // 3. Converging Payment Data Particles (Particles flowing in vortex into gate)
  const particleCount = 1800;
  const particleGeo = new THREE.BufferGeometry();
  const positions = new Float32Array(particleCount * 3);
  const colors = new Float32Array(particleCount * 3);
  const speeds = new Float32Array(particleCount);
  const angles = new Float32Array(particleCount);
  const radii = new Float32Array(particleCount);
  const heights = new Float32Array(particleCount);

  const c1 = new THREE.Color(0x38bdf8); // Cyan
  const c2 = new THREE.Color(0x10b981); // Emerald
  const c3 = new THREE.Color(0xf59e0b); // Gold

  for (let i = 0; i < particleCount; i++) {
    radii[i] = 6 + Math.random() * 32;
    angles[i] = Math.random() * Math.PI * 2;
    heights[i] = (Math.random() - 0.5) * 28;
    speeds[i] = 0.008 + Math.random() * 0.02;

    positions[i * 3] = Math.cos(angles[i]) * radii[i];
    positions[i * 3 + 1] = heights[i];
    positions[i * 3 + 2] = Math.sin(angles[i]) * radii[i];

    // Randomized color blend
    const rnd = Math.random();
    const col = rnd < 0.6 ? c1 : (rnd < 0.85 ? c2 : c3);
    colors[i * 3] = col.r;
    colors[i * 3 + 1] = col.g;
    colors[i * 3 + 2] = col.b;
  }

  particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
  particleGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));

  // Particle Material with Soft Glow Sprite
  const canvasGlow = document.createElement('canvas');
  canvasGlow.width = 64;
  canvasGlow.height = 64;
  const ctx = canvasGlow.getContext('2d');
  const gradient = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
  gradient.addColorStop(0, 'rgba(255,255,255,1)');
  gradient.addColorStop(0.3, 'rgba(56,189,248,0.8)');
  gradient.addColorStop(0.8, 'rgba(14,116,144,0.2)');
  gradient.addColorStop(1, 'rgba(0,0,0,0)');
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 64, 64);
  const glowTexture = new THREE.CanvasTexture(canvasGlow);

  const particleMat = new THREE.PointsMaterial({
    size: 0.65,
    vertexColors: true,
    map: glowTexture,
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });

  const particleSystem = new THREE.Points(particleGeo, particleMat);
  worldGroup.add(particleSystem);

  // 4. Lights
  const ambientLight = new THREE.AmbientLight(0x0f172a, 1.5);
  scene.add(ambientLight);

  const cyanLight = new THREE.PointLight(0x38bdf8, 3.5, 50);
  cyanLight.position.set(10, 10, 10);
  scene.add(cyanLight);

  const emeraldLight = new THREE.PointLight(0x10b981, 3.0, 50);
  emeraldLight.position.set(-10, -10, 8);
  scene.add(emeraldLight);

  // Mouse Interactivity
  let mouseX = 0;
  let mouseY = 0;
  let targetMouseX = 0;
  let targetMouseY = 0;
  const windowHalfX = window.innerWidth / 2;
  const windowHalfY = window.innerHeight / 2;

  window.addEventListener('mousemove', (e) => {
    targetMouseX = (e.clientX - windowHalfX) * 0.0012;
    targetMouseY = (e.clientY - windowHalfY) * 0.0012;
  });

  // Click Energy Burst Ripple
  window.addEventListener('click', (e) => {
    // Pulse effect on gate core
    coreMat.emissiveIntensity = 3.5;
    knotMat.opacity = 0.9;
    setTimeout(() => {
      coreMat.emissiveIntensity = 1.2;
      knotMat.opacity = 0.45;
    }, 450);
  });

  // Resize handler
  window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  });

  // Animation Loop
  let clock = new THREE.Clock();

  function animate() {
    requestAnimationFrame(animate);
    const elapsedTime = clock.getElapsedTime();

    // Smooth mouse lerp
    mouseX += (targetMouseX - mouseX) * 0.05;
    mouseY += (targetMouseY - mouseY) * 0.05;

    worldGroup.rotation.y = mouseX * 1.5 + elapsedTime * 0.05;
    worldGroup.rotation.x = mouseY * 1.2;

    // Rotate Gate core & knot
    knotMesh.rotation.x = elapsedTime * 0.35;
    knotMesh.rotation.y = elapsedTime * 0.45;
    knotMesh.rotation.z = Math.sin(elapsedTime * 0.5) * 0.2;

    coreMesh.rotation.y = -elapsedTime * 0.6;
    const pulseScale = 1 + Math.sin(elapsedTime * 3) * 0.08;
    coreMesh.scale.set(pulseScale, pulseScale, pulseScale);

    // Rotate Concentric Security Rings
    rings.forEach((r, idx) => {
      r.mesh.rotation.z += r.speedY;
      r.mesh.rotation.y += r.speedX;
      r.mesh.scale.setScalar(1 + Math.sin(elapsedTime * 2 + idx) * 0.03);
    });

    // Update converging particles vortex
    const pos = particleGeo.attributes.position.array;
    for (let i = 0; i < particleCount; i++) {
      angles[i] += speeds[i];
      // Slow gravitational vortex attraction towards center
      radii[i] -= 0.035;
      if (radii[i] < 4.5) {
        radii[i] = 28 + Math.random() * 8;
        heights[i] = (Math.random() - 0.5) * 24;
      }

      pos[i * 3] = Math.cos(angles[i]) * radii[i];
      pos[i * 3 + 1] = heights[i] + Math.sin(elapsedTime * 2 + i) * 0.5;
      pos[i * 3 + 2] = Math.sin(angles[i]) * radii[i];
    }
    particleGeo.attributes.position.needsUpdate = true;

    renderer.render(scene, camera);
  }

  animate();
})();
