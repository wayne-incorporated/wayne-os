#version 310 es

precision highp float;

uniform highp mat4 uTextureMatrix;

layout(location = 0) in highp vec2 vXY;
layout(location = 0) out highp vec2 vTexCoord;

void main() {
  gl_Position = vec4(vXY, 0.0, 1.0);
  vTexCoord = (uTextureMatrix * vec4(vXY, 0.0, 1.0)).xy;
}
