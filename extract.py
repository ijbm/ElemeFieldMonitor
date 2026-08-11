import lzma, tarfile, io, os, shutil

deb_path = r'I:\ios\ElemeFieldMonitor\build_output\packages\com.eleme.fieldmonitor_1.0.0-1+debug_iphoneos-arm64.deb'
out_dir = r'I:\ios\ElemeFieldMonitor\build_output'

with open(deb_path, 'rb') as f:
    data = f.read()

# Parse AR archive
pos = 8  # skip "!<arch>\n"
files = {}
while pos < len(data):
    name = data[pos:pos+16].decode('ascii').strip()
    size_str = data[pos+48:pos+58].decode('ascii').strip()
    pos += 60
    size = int(size_str)
    content = data[pos:pos+size]
    files[name] = content
    pos += size
    if size % 2 == 1:
        pos += 1

# Find and decompress data.tar.lzma
for k, v in files.items():
    if 'data.tar.lzma' in k:
        decompressed = lzma.decompress(v)
        with tarfile.open(fileobj=io.BytesIO(decompressed), mode='r:') as tar:
            tar.extractall(os.path.join(out_dir, 'extracted'))
        break

# Copy dylib and plist
src_dylib = os.path.join(out_dir, 'extracted', 'var', 'jb', 'Library', 'MobileSubstrate', 'DynamicLibraries', 'ElemeFieldMonitor.dylib')
dst_dylib = os.path.join(out_dir, 'ElemeFieldMonitor.dylib')
shutil.copy2(src_dylib, dst_dylib)
print(f'dylib size: {os.path.getsize(dst_dylib)}')

src_plist = os.path.join(out_dir, 'extracted', 'var', 'jb', 'Library', 'MobileSubstrate', 'DynamicLibraries', 'ElemeFieldMonitor.plist')
dst_plist = os.path.join(out_dir, 'ElemeFieldMonitor.plist')
shutil.copy2(src_plist, dst_plist)
print(f'plist size: {os.path.getsize(dst_plist)}')
print('Done!')
