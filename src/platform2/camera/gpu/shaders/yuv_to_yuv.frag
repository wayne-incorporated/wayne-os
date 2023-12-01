#version 310 es

precision highp float;

layout(binding = 0) uniform highp sampler2D uInputYTexture;
layout(binding = 1) uniform highp sampler2D uInputUvTexture;

layout(location = 0) uniform bool uIsYPlane;

layout(location = 0) in highp vec2 vTexCoord;
layout(location = 0) out highp vec4 outColor;

void main() {
  if (uIsYPlane) {
    float y = texture(uInputYTexture, vTexCoord).r;
    outColor = vec4(y, 0.0, 0.0, 0.0);
  } else {
    vec2 uv = texture(uInputUvTexture, vTexCoord).rg;
    outColor = vec4(uv, 0.0, 0.0);
  }
}

