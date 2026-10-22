# Zero Breach (bản Rust)

## Nguồn / Ghi công

Đây là **bản port sang Rust không chính thức** của
[zero-breach](https://github.com/interplains/zero-breach) — *adint-scan*, công
cụ quét cục bộ, chỉ đọc, tìm dấu vết phần mềm gián điệp AdFection / Candiru —
**Copyright 2026 archivegenocide.com**, giấy phép **Apache-2.0** (`LICENSE`).
Bản port theo upstream **commit `1c7e9b6`** (bản phát hành v0.1.8) và port
trực tiếp từng file của phần quét (`scan/adint_scan`).

**Dữ liệu chỉ số (IOC)** (`iocs/adfection_iocs.txt`) thuộc sở hữu công cộng
CC0, lấy từ cùng repo (`iocs/LICENSE.md`). Nó được nhúng vào file thực thi và
để sẵn trong thư mục `iocs/`.

Nghiên cứu nền mà công cụ dựa vào:

- The Citizen Lab, *Exposing AdFection: How Discover-Tech Turned Targeted Ads
  Into a Pipeline for Zero-Click Mercenary Spyware* (2026-10-15) —
  <https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/>
- Recorded Future / Insikt Group, *Tracking Candiru's DevilsTongue Spyware*
  (CTA-2025-0805, 2025-08-05) —
  <https://www.recordedfuture.com/research/tracking-candirus-devilstongue-spyware>

Dự án này **không liên kết với và không được chứng thực bởi** zero-breach /
archivegenocide.com, The Citizen Lab, Recorded Future, Amnesty International,
Access Now hay bất kỳ tổ chức nào nêu trên. Tên của họ chỉ xuất hiện để ghi rõ
nguồn của chỉ số hoặc để chỉ nơi nhận hỗ trợ chuyên môn. Mọi lỗi của bản port
này là của riêng nó; xem `NOTICE`.

> **Kết quả "không tìm thấy" KHÔNG có nghĩa là máy bạn sạch.** Phần mềm gián
> điệp loại này được thiết kế để vượt qua kiểu quét này, phần lớn dấu vết chỉ
> tồn tại vài tuần, và Windows không ghi lịch sử DNS trừ khi có người bật lên.
> Nếu bạn có cơ sở thật để nghi ngờ mình bị nhắm tới, bước đúng là tìm đến
> người có chuyên môn —
> [Access Now Digital Security Helpline](https://www.accessnow.org/help/) hoặc
> [Amnesty International Security Lab](https://securitylab.amnesty.org/) —
> chứ không phải tự chạy công cụ này rồi yên tâm.

## Công cụ làm gì

`zero-breach scan` tìm dấu vết của chiến dịch **AdFection / Candiru** — chiến
dịch dùng đấu giá quảng cáo thời gian thực để phát phần mềm gián điệp không
cần bấm chuột. Nó đọc các dấu vết còn lại trên máy: lịch sử duyệt web, cookie
(chỉ tên miền và dấu thời gian, không đọc giá trị cookie), bộ nhớ đệm, bản ghi
kết nối, vân tay file, đăng ký tự khởi động (COM), các đường dẫn file phần
xấu đã biết và bộ đệm DNS của máy — rồi báo cáo tìm được gì, bằng chứng mạnh
mạnh tới đâu, và quan trọng không kém: **những chỗ nó không kiểm tra được**.

Mỗi kết quả được **phân loại bằng chứng** (`on-disk`, `persistence`,
`contacted`, `dns-record`, `attempted`, `configured`, `referenced`), vì chính
dấu vết quyết định ý nghĩa: một tên miền xuất hiện trong bài báo lưu trong bộ
đệm không phải là kết nối tới nó. Một bản ghi DNS trỏ về địa chỉ chặn là cấu
hình bảo vệ, không phải tiếp xúc. Tên miền được in dạng vô hiệu
(`example[.]com`) để khi chuyển tiếp báo cáo, chương trình thư không tự "bấm
vào" chúng.

Chỉ đọc hoàn toàn: cơ sở dữ liệu trình duyệt được **sang thư mục tạm** rồi mở
bản sao (không bao giờ ghi vào profile), không ghi registry, không sửa file
hosts hay cài đặt DNS, và không bao giờ phân giải hay kết nối tới chỉ số nào —
toàn bộ đường mã quét không chứa mã mạng nào cả.

## Build và chạy

```
cargo build --release
cargo run --release -- scan                # quét đầy đủ
cargo run --release -- scan --quick        # bỏ qua vân tay file (báo là khoảng trống)
cargo run --release -- scan --json out.json
cargo run --release -- scan --iocs /duong/dan/iocs.txt
```

Không cần quyền quản trị. Mã thoát: `0` không tìm thấy, `2` có chỉ số khớp,
`1` không thiết lập được lượt quét (ví dụ file chỉ số hỏng).

`--json` ghi báo cáo máy đọc được với cùng các trường như bản gốc (`tool`,
`timestamp`, `platform`, `ioc_set`, `modules`, `verdict`, `doctrine_line`);
báo cáo dạng chữ in ra stdout.

`--iocs` / `--json` từ chối đường dẫn không nằm trên đĩa cục bộ, đúng như bản
gốc v0.1.8: đường dẫn UNC hoặc ổ đĩa mạng sẽ khiến Windows tự mở phiên SMB —
lộ thông tin đăng nhập và, với `--json`, toàn bộ báo cáo.

### update-iocs (lệnh con duy nhất dùng mạng)

```
cargo run --release -- update-iocs                  # chạy thử: tải, kiểm tra, in khác biệt
cargo run --release -- update-iocs --apply          # thay file chỉ số cục bộ
```

Lệnh này tải `adfection_iocs.txt` và `.sha256` từ URL raw của dự án gốc qua
HTTPS (bật xác minh chứng chỉ), chỉ chấp nhận HTTPS, so byte tải về với hash
đã công bố, kiểm tra file tải về còn phân tích được và không rỗng, in phần
khác biệt, và — chỉ khi có `--apply` — thay file cục bộ bằng cách ghi file tạm
cùng thư mục rồi đổi tên nguyên tử. Lệnh `scan` không bao giờ dùng mạng.

## Đã port những gì

Xem bảng chi tiết trong `README.md` (bản tiếng Anh). Tóm tắt:

- Đã port: `cli`, `iocs`, `localpaths`, `netguard`, `context`, `result`,
  `report`, các module `browser`, `hashscan`, `host` (phần Windows nằm sau
  `#[cfg(windows)]`; trên macOS/Linux báo "not supported on \<os\>" — không bao
  giờ báo CLEAN giả), `update-iocs` và phần lớn bộ kiểm thử.
- **Chưa port:** `build/` (bộ phát STIX / MISP / danh sách chặn) và `tools/`
  — đó là công cụ đóng gói của bản Python, không phải hành vi quét.
- **Kiểm tra mẫu file (YARA) là stub:** bản này không nhúng engine YARA-X và
  hai quy tắc Candiru của bên thứ ba; `--patterns` sẽ báo "pattern scan not
  available in this build" như một khoảng trống, không bao giờ báo sạch.

## Khác biệt nhỏ so với bản Python

- Dấu thời gian hiển thị theo **UTC** (bản gốc theo múi giờ máy).
- Trường `platform.python` trong JSON ghi phiên bản toolchain Rust.
- File `--iocs` không phải UTF-8 hợp lệ báo lỗi gọn thay vì traceback.

## Kiểm thử

```
cargo test                 # 166 kiểm thử
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Mọi kiểm thử chạy trong thư mục tạm với chỉ số hậu tố `.invalid` (không thể
phân giải); việc khoá cơ sở dữ liệu trình duyệt được giả lập bằng hook tiêm
vào, không đụng vào trình duyệt thật. Mã Windows được kiểm tra bằng
`cargo check --target x86_64-pc-windows-gnu` (mingw-w64) và build link đầy đủ.

CI chạy kiểm thử và clippy trên Ubuntu, Windows và macOS, và build file phát
hành khi có tag `v*`.

## Giấy phép

Phần mềm theo **Apache License 2.0** (`LICENSE`). Dữ liệu chỉ số trong
`iocs/` thuộc sở hữu công cộng **CC0 1.0** (`iocs/LICENSE.md`). `NOTICE` của
dự án gốc được giữ nguyên văn, kèm một dòng ghi công bản port. Dự án này
không liên kết với và không được chứng thực bởi dự án gốc hay bất kỳ tổ chức
nghiên cứu nào nêu trên.
