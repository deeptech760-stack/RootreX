/* eye.js — the Evil Eye.
 * A procedural WebGL flame-iris eye. Ported from the OGL/React project
 * sebastianvasquezechavarria1234/evil-aye (MIT) to a dependency-free module on
 * the #eye-bg canvas: the "Volcanic Flare" preset, the pupil tracking the cursor,
 * and a transparent background so it glows over the RootreX UI. Bottom layer.
 */
(() => {
  "use strict";
  const cv = document.getElementById("eye-bg");
  if (!cv) return;
  const gl = cv.getContext("webgl", { alpha: true, premultipliedAlpha: false, antialias: true });
  if (!gl) return;

  // ---- Volcanic Flare preset (from evil-aye) ----
  const P = {
    eyeColor: "#FF5A2A",        // volcanic red-orange (slightly hotter/redder than #FF6F37)
    intensity: 2.0, pupilSize: 0.7, irisWidth: 0.2, glowIntensity: 0.6,
    scale: 0.9, noiseScale: 1.5, pupilFollow: 1.0, flameSpeed: 1.8,
  };
  const hex3 = (h) => { h = h.replace("#", ""); return [parseInt(h.slice(0, 2), 16) / 255, parseInt(h.slice(2, 4), 16) / 255, parseInt(h.slice(4, 6), 16) / 255]; };

  // ---- fractal value-noise texture (ported verbatim) ----
  function noiseTexture(size) {
    const data = new Uint8Array(size * size * 4);
    const hash = (x, y, s) => { let n = x * 374761393 + y * 668265263 + s * 1274126177; n = Math.imul(n ^ (n >>> 13), 1274126177); return ((n ^ (n >>> 16)) >>> 0) / 4294967296; };
    const noise = (px, py, freq, seed) => {
      const fx = (px / size) * freq, fy = (py / size) * freq;
      const ix = Math.floor(fx), iy = Math.floor(fy), tx = fx - ix, ty = fy - iy, w = freq | 0;
      const v00 = hash(((ix % w) + w) % w, ((iy % w) + w) % w, seed);
      const v10 = hash((((ix + 1) % w) + w) % w, ((iy % w) + w) % w, seed);
      const v01 = hash(((ix % w) + w) % w, (((iy + 1) % w) + w) % w, seed);
      const v11 = hash((((ix + 1) % w) + w) % w, (((iy + 1) % w) + w) % w, seed);
      return v00 * (1 - tx) * (1 - ty) + v10 * tx * (1 - ty) + v01 * (1 - tx) * ty + v11 * tx * ty;
    };
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
      let v = 0, amp = 0.4, tot = 0;
      for (let o = 0; o < 8; o++) { const f = 32 * (1 << o); v += amp * noise(x, y, f, o * 31); tot += amp; amp *= 0.65; }
      v = Math.max(0, Math.min(1, (v / tot - 0.5) * 2.2 + 0.5));
      const val = Math.round(v * 255), i = (y * size + x) * 4;
      data[i] = data[i + 1] = data[i + 2] = val; data[i + 3] = 255;
    }
    return data;
  }

  const VERT = `attribute vec2 position; void main(){ gl_Position = vec4(position, 0.0, 1.0); }`;
  const FRAG = `
precision highp float;
uniform float uTime; uniform vec3 uResolution; uniform sampler2D uNoiseTexture;
uniform float uPupilSize, uIrisWidth, uGlowIntensity, uIntensity, uScale, uNoiseScale, uPupilFollow, uFlameSpeed;
uniform vec2 uMouse; uniform vec3 uEyeColor, uBgColor;
void main() {
  vec2 uv = (gl_FragCoord.xy * 2.0 - uResolution.xy) / uResolution.y;
  uv /= uScale;
  float ft = uTime * uFlameSpeed;
  float polarRadius = length(uv) * 2.0;
  float polarAngle = (2.0 * atan(uv.x, uv.y)) / 6.28 * 0.3;
  vec2 polarUv = vec2(polarRadius, polarAngle);
  vec4 noiseA = texture2D(uNoiseTexture, polarUv * vec2(0.2, 7.0) * uNoiseScale + vec2(-ft * 0.1, 0.0));
  vec4 noiseB = texture2D(uNoiseTexture, polarUv * vec2(0.3, 4.0) * uNoiseScale + vec2(-ft * 0.2, 0.0));
  vec4 noiseC = texture2D(uNoiseTexture, polarUv * vec2(0.1, 5.0) * uNoiseScale + vec2(-ft * 0.1, 0.0));
  float distanceMask = 1.0 - length(uv);
  float innerRing = clamp(-1.0 * ((distanceMask - 0.7) / uIrisWidth), 0.0, 1.0);
  innerRing = (innerRing * distanceMask - 0.2) / 0.28; innerRing += noiseA.r - 0.5; innerRing *= 1.3; innerRing = clamp(innerRing, 0.0, 1.0);
  float outerRing = clamp(-1.0 * ((distanceMask - 0.5) / 0.2), 0.0, 1.0);
  outerRing = (outerRing * distanceMask - 0.1) / 0.38; outerRing += noiseC.r - 0.5; outerRing *= 1.3; outerRing = clamp(outerRing, 0.0, 1.0);
  innerRing += outerRing;
  float innerEye = distanceMask - 0.1 * 2.0; innerEye *= noiseB.r * 2.0;
  vec2 pupilOffset = uMouse * uPupilFollow * 0.12;
  vec2 pupilUv = uv - pupilOffset;
  float pupil = 1.0 - length(pupilUv * vec2(9.0, 2.3)); pupil *= uPupilSize; pupil = clamp(pupil, 0.0, 1.0); pupil /= 0.35;
  float outerEyeGlow = 1.0 - length(uv * vec2(0.5, 1.5)); outerEyeGlow = clamp(outerEyeGlow + 0.5, 0.0, 1.0); outerEyeGlow += noiseC.r - 0.5;
  float outerBgGlow = outerEyeGlow;
  outerEyeGlow = pow(outerEyeGlow, 2.0); outerEyeGlow += distanceMask; outerEyeGlow *= uGlowIntensity; outerEyeGlow = clamp(outerEyeGlow, 0.0, 1.0); outerEyeGlow *= pow(1.0 - distanceMask, 2.0) * 2.5;
  outerBgGlow += distanceMask; outerBgGlow = pow(outerBgGlow, 0.5); outerBgGlow *= 0.15;
  vec3 color = uEyeColor * uIntensity * clamp(max(innerRing + innerEye, outerEyeGlow + outerBgGlow) - pupil, 0.0, 3.0);
  color += uBgColor;
  float a = clamp(max(max(color.r, color.g), color.b), 0.0, 1.0);   // transparent where no eye -> glows over the UI
  gl_FragColor = vec4(color, a);
}`;

  function compile(type, src) { const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) { console.error(gl.getShaderInfoLog(s)); return null; } return s; }
  const prog = gl.createProgram();
  gl.attachShader(prog, compile(gl.VERTEX_SHADER, VERT));
  gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FRAG));
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) { console.error(gl.getProgramInfoLog(prog)); return; }
  gl.useProgram(prog);

  // fullscreen triangle
  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, "position");
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

  // noise texture
  const tex = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D, tex);
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 256, 256, 0, gl.RGBA, gl.UNSIGNED_BYTE, noiseTexture(256));
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.REPEAT);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);

  const U = {};
  for (const n of ["uTime", "uResolution", "uNoiseTexture", "uPupilSize", "uIrisWidth", "uGlowIntensity", "uIntensity", "uScale", "uNoiseScale", "uMouse", "uPupilFollow", "uFlameSpeed", "uEyeColor", "uBgColor"]) U[n] = gl.getUniformLocation(prog, n);
  gl.uniform1i(U.uNoiseTexture, 0);
  gl.uniform1f(U.uPupilSize, P.pupilSize); gl.uniform1f(U.uIrisWidth, P.irisWidth);
  gl.uniform1f(U.uGlowIntensity, P.glowIntensity); gl.uniform1f(U.uIntensity, P.intensity);
  gl.uniform1f(U.uScale, P.scale); gl.uniform1f(U.uNoiseScale, P.noiseScale);
  gl.uniform1f(U.uPupilFollow, P.pupilFollow); gl.uniform1f(U.uFlameSpeed, P.flameSpeed);
  gl.uniform3fv(U.uEyeColor, hex3(P.eyeColor)); gl.uniform3fv(U.uBgColor, [0, 0, 0]);

  gl.enable(gl.BLEND);
  gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
  gl.clearColor(0, 0, 0, 0);

  // Render well below CSS resolution — the eye lives behind blurred glass panels,
  // so softness is invisible but the per-pixel shader cost drops ~3x.
  const RES = 0.55;
  function resize() {
    const w = Math.max(2, Math.round(innerWidth * RES)), h = Math.max(2, Math.round(innerHeight * RES));
    cv.width = w; cv.height = h; gl.viewport(0, 0, w, h);
    gl.uniform3f(U.uResolution, w, h, w / h);
  }
  addEventListener("resize", () => { clearTimeout(resize._t); resize._t = setTimeout(resize, 150); });
  resize();

  const m = { x: 0, y: 0, tx: 0, ty: 0 };
  addEventListener("mousemove", (e) => { m.tx = (e.clientX / innerWidth) * 2 - 1; m.ty = -((e.clientY / innerHeight) * 2 - 1); });

  let last = 0;
  function frame(t) {
    requestAnimationFrame(frame);
    if (t - last < 33) return;   // cap ~30fps — halves GPU vs 60fps
    last = t;
    m.x += (m.tx - m.x) * 0.05; m.y += (m.ty - m.y) * 0.05;
    gl.uniform2f(U.uMouse, m.x, m.y);
    gl.uniform1f(U.uTime, t * 0.001);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }
  requestAnimationFrame(frame);
})();
