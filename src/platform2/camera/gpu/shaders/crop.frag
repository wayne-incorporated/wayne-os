#version 310 es

precision highp float;

layout(binding = 0) uniform highp sampler2D uInputTexture;
layout(location = 1) uniform vec4 uCropRegion;
layout(location = 2) uniform bool uBicubic;

layout(location = 0) in highp vec2 vTexCoord;
layout(location = 0) out highp vec4 outColor;

// Computes cubic B-spline filtering kernel coefficients on v-1, v, v+1, v+2.
vec4 cubic(float v) {
  vec4 n = vec4(1.0, 2.0, 3.0, 4.0) - v;
  vec4 s = n * n * n;
  float x = s.x;
  float y = s.y - 4.0 * s.x;
  float z = s.z - 4.0 * s.y + 6.0 * s.x;
  float w = 6.0 - x - y - z;
  return vec4(x, y, z, w) / 6.0;
}

// Samples 2D texture with bicubic filtering.
vec4 textureBicubic(sampler2D sampler, vec2 texCoords) {
  vec2 texSize = vec2(textureSize(sampler, 0));
  vec2 invTexSize = 1.0 / texSize;

  texCoords = texCoords * texSize - 0.5;

  vec2 fxy = fract(texCoords);
  texCoords -= fxy;

  vec4 xcubic = cubic(fxy.x);
  vec4 ycubic = cubic(fxy.y);

  vec4 c = texCoords.xxyy + vec2(-0.5, 1.5).xyxy;
  vec4 s = vec4(xcubic.xz + xcubic.yw, ycubic.xz + ycubic.yw);
  vec4 d = (c + vec4(xcubic.yw, ycubic.yw) / s) * invTexSize.xxyy;

  vec4 sample0 = texture(sampler, d.xz);
  vec4 sample1 = texture(sampler, d.yz);
  vec4 sample2 = texture(sampler, d.xw);
  vec4 sample3 = texture(sampler, d.yw);

  return mix(mix(sample0, sample1, s.y), mix(sample2, sample3, s.y), s.w);
}

void main() {
  float src_x = uCropRegion.x;
  float src_y = uCropRegion.y;
  float crop_width = uCropRegion.z;
  float crop_height = uCropRegion.w;
  vec2 sample_coord = vec2(
      src_x + vTexCoord.x * crop_width,
      src_y + vTexCoord.y * crop_height);
  if (uBicubic) {
    outColor = textureBicubic(uInputTexture, sample_coord);
  } else {
    outColor = texture(uInputTexture, sample_coord);
  }
}
