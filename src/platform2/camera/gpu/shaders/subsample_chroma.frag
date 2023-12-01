#version 310 es

precision highp float;

layout(binding = 0) uniform highp sampler2D uInputUvTexture;

layout(location = 0) in highp vec2 vTexCoord;
layout(location = 0) out highp vec4 outColor;

void main() {
  vec2 uv = texture(uInputUvTexture, vTexCoord).rg;
  outColor = vec4(uv, 0.0, 0.0);
}
