require 'zlib'

def png_chunk(type, data)
  type = type.b
  data = data.b
  [data.bytesize].pack('N') + type + data + [Zlib.crc32(type + data)].pack('N')
end

def segment_distance(px, py, x1, y1, x2, y2)
  dx = x2 - x1
  dy = y2 - y1
  length = dx * dx + dy * dy
  t = length.zero? ? 0 : [[((px - x1) * dx + (py - y1) * dy) / length.to_f, 0].max, 1].min
  Math.sqrt((px - x1 - t * dx)**2 + (py - y1 - t * dy)**2)
end

def inside_round_rect?(x, y, left, top, right, bottom, radius)
  cx = [[x, left + radius].max, right - radius].min
  cy = [[y, top + radius].max, bottom - radius].min
  (x - cx)**2 + (y - cy)**2 <= radius**2
end

def render_png(size)
  scale = 4
  high = size * scale
  samples = Array.new(high * high)
  diamond = [[32, 18], [46, 32], [32, 46], [18, 32], [32, 18]]
  high.times do |y|
    high.times do |x|
      px = (x + 0.5) * 64 / high
      py = (y + 0.5) * 64 / high
      if inside_round_rect?(px, py, 1, 1, 63, 63, 17)
        t = (px * 0.36 + py * 0.64) / 64
        top = [52, 121, 242]
        bottom = [36, 82, 200]
        color = 3.times.map { |i| (top[i] * (1 - t) + bottom[i] * t).round } + [255]
        ring_distance = Math.sqrt((px - 32)**2 + (py - 32)**2)
        color = [255, 255, 255, 210] if (ring_distance - 20).abs < 1.55
        on_diamond = diamond.each_cons(2).any? { |a, b| segment_distance(px, py, a[0], a[1], b[0], b[1]) < 2.1 }
        color = [255, 255, 255, 255] if on_diamond
        color = [103, 224, 203, 255] if (px - 32)**2 + (py - 32)**2 <= 5.2**2
        samples[y * high + x] = color
      else
        samples[y * high + x] = [0, 0, 0, 0]
      end
    end
  end

  raw = String.new(encoding: Encoding::BINARY)
  size.times do |y|
    raw << "\0"
    size.times do |x|
      channels = [0, 0, 0, 0]
      scale.times do |sy|
        scale.times do |sx|
          px = x * scale + sx
          py = y * scale + sy
          color = samples[py * high + px]
          4.times { |c| channels[c] += color[c] }
        end
      end
      channels.map! { |v| (v.to_f / (scale * scale)).round }
      raw << channels.pack('C4')
    end
  end
  header = [size, size, 8, 6, 0, 0, 0].pack('NNC5')
  "\x89PNG\r\n\x1a\n".b + png_chunk('IHDR', header) + png_chunk('IDAT', Zlib::Deflate.deflate(raw, Zlib::BEST_COMPRESSION)) + png_chunk('IEND', ''.b)
end

sizes = [16, 32, 48]
images = sizes.map { |size| [size, render_png(size)] }
offset = 6 + images.length * 16
directory = [0, 1, images.length].pack('v3')
entries = String.new(encoding: Encoding::BINARY)
images.each do |size, png|
  entries << [size == 256 ? 0 : size, size == 256 ? 0 : size, 0, 0, 1, 32, png.bytesize, offset].pack('C4v2V2')
  offset += png.bytesize
end
File.binwrite(File.expand_path('../assets/favicon.ico', __dir__), directory + entries + images.map(&:last).join)
