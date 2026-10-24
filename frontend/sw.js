// Service worker tối giản: chỉ để trình duyệt cho phép cài thành ứng dụng.
// Không lưu bộ nhớ đệm, nên luôn lấy bản mới nhất và dữ liệu điểm danh luôn trực tiếp.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});
