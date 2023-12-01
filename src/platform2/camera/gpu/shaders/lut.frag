#version 310 es

precision highp float;

layout(binding = 0) uniform highp sampler2D uInputRgbaTexture;
layout(binding = 1) uniform highp sampler2D uRLutTexture;
layout(binding = 2) uniform highp sampler2D uGLutTexture;
layout(binding = 3) uniform highp sampler2D uBLutTexture;

layout(location = 0) in highp vec2 vTexCoord;
layout(location = 0) out highp vec4 outColor;

void main() {
  vec3 rgb = texture(uInputRgbaTexture, vTexCoord).rgb;
  outColor = vec4(texture(uRLutTexture, vec2(rgb.r, 0.0)).r,
                  texture(uGLutTexture, vec2(rgb.g, 0.0)).r,
                  texture(uBLutTexture, vec2(rgb.b, 0.0)).r,
                  1.0);
}
