#version 310 es

precision highp float;

layout(binding = 0) uniform highp sampler2D uInputYTexture;
layout(binding = 1) uniform highp sampler2D uInputUvTexture;

layout(location = 0) in highp vec2 vTexCoord;
layout(location = 0) out highp vec4 outColor;

void main() {
  float y = texture(uInputYTexture, vTexCoord).r;
  float u = texture(uInputUvTexture, vTexCoord).r;
  float v = texture(uInputUvTexture, vTexCoord).g;

  vec3 rgb = clamp(vec3(
    y + 1.4017 * (v - 0.5),
    y - 0.3437 * (u - 0.5) - 0.7142 * (v - 0.5),
    y + 1.7722 * (u - 0.5)
  ), 0.0, 1.0);

  outColor = vec4(rgb, 1.0);
}
