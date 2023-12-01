#version 310 es

precision highp float;

layout(binding = 0) uniform highp sampler2D uInputRgbaTexture;
layout(location = 0) uniform bool uIsYPlane;

layout(location = 0) in highp vec2 vTexCoord;
layout(location = 0) out highp vec4 outColor;

void main() {
  vec3 rgb = texture(uInputRgbaTexture, vTexCoord).rgb;
  if (uIsYPlane) {
    float y = 0.299 * rgb.r + 0.587 * rgb.g + 0.114 * rgb.b;
    outColor = vec4(y, 0.0, 0.0, 0.0);
  } else {
    float u = -0.16874 * rgb.r - 0.33126 * rgb.g + 0.5 * rgb.b + 0.5;
    float v = 0.5 * rgb.r - 0.41869 * rgb.g - 0.08131 * rgb.b + 0.5;
    outColor = vec4(u, v, 0.0, 0.0);
  }
}
