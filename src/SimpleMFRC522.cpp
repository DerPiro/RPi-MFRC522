#include "mfrc522/SimpleMFRC522.hpp"

#include <algorithm>

namespace mfrc522 {
std::string byte_to_hex(byte b) {
  static const char h[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
  std::string       out{};
  out += "0x";
  out += h[b >> 4];
  out += h[b & 0x0F];
  return out;
}

/*
explicit std::ostream& operator<<(std::ostream& out, const byte b) {
  static const char hex_char[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                   '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
  out << R"(0x)" << hex_char[b >> 4] << hex_char[b & 0x0F];
  return out;
}
*/

const int                  SimpleMFRC522::block_size{ 16 };
const std::array<byte, 47> SimpleMFRC522::BLOCK_ADDRS{
  {1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 18, 20, 21,
   22, 24, 25, 26, 28, 29, 30, 32, 33, 34, 36, 37, 38, 40, 41, 42,
   44, 45, 46, 48, 49, 50, 52, 53, 54, 56, 57, 58, 60, 61, 62}
};

SimpleMFRC522::SimpleMFRC522(int ss_pin, int rst_pin, int spi_channel)
    : MFRC522{ ss_pin, rst_pin, spi_channel } {
  PCD_Init();

  for (int i = 0; i < 6; ++i) {
    key_a.keyByte[i] = 0xFF;
    key_b.keyByte[i] = 0xFF;
  }

  /*
  for (byte i = 0; i < 64; ++i) {
    if (!(i == 0 || i == i + (4 - i % 4) - 1)) {
      BLOCK_ADDRS.push_back(i);
    }
  }
  */
}

Uid* SimpleMFRC522::getUid() {
  return select_card();
}

uint64_t SimpleMFRC522::uid_to_num(const Uid* const uid) {
  if (uid == nullptr || uid->size > 8)
    return 0;
  uint64_t out{};
  for (int i = 0; i < uid->size; ++i) {
    out = (out << 8) | uid->uidByte[i];
  }
  return out;
}

bool SimpleMFRC522::is_available() {
  select_card();
  return 0;
}

Uid* SimpleMFRC522::select_card() {
  int i;
  for (i = 0; i < 3; ++i) {
    byte buffer[2]{};
    byte size{ 2 };
    PICC_WakeupA(buffer, &size);
    if (PICC_ReadCardSerial() == StatusCode::STATUS_OK) {
      break;
    }
  }
  if (i == 3) {
    uid = Uid{};
    return nullptr;
  }
  return &uid;
}

int SimpleMFRC522::read_block(byte block, std::span<byte> buffer) {
  if (!select_card())
    return 0;
  int trailer_block = block + (4 - block % 4) - 1;
  if (PCD_Authenticate(PICC_Command::PICC_CMD_MF_AUTH_KEY_A, trailer_block,
                       &key_a, &uid)
      != StatusCode::STATUS_OK)
    return 0;
  byte size = buffer.size();
  if (MIFARE_Read(block, buffer.data(), (byte*) &size)
      != StatusCode::STATUS_OK) {
    stop_comm();
    return 0;
  }
  stop_comm();
  return size;
}

int SimpleMFRC522::read_no_block(std::span<byte> buffer) {
  std::span<byte> cur_view;
  int             bytes{ 0 };
  for (int i = 0, j = 0; i < buffer.size(); i += block_size, ++j) {
    cur_view = buffer.subspan(i, block_size);
    byte cur_buffer[block_size + 2]{};
    bytes += read_block(BLOCK_ADDRS[j], cur_buffer) - 2;
    for (int x = 0; x < block_size; ++x) {
      cur_view[x] = cur_buffer[x];
    }
  }
  return bytes;
}

int SimpleMFRC522::read(std::string* str) {
  str->clear();
  read_no_block({ (byte*) str->data(), str->size() });
  {
    str->erase(str->begin(),
               std::find_if(str->begin(), str->end(), [](unsigned char ch) {
                 return !std::isspace(ch);
               }));
    str->erase(std::find_if(str->rbegin(), str->rend(),
                            [](unsigned char ch) { return !std::isspace(ch); })
                   .base(),
               str->end());
  }
  return str->length();
}

int SimpleMFRC522::write_block(byte block, const std::span<byte> buffer) {
  if ((block + 1) % 4 == 0 || block == 0)
    return 0;
  if (!select_card())
    return 0;
  int trailer_block = block + (4 - block % 4) - 1;
  if (PCD_Authenticate(PICC_Command::PICC_CMD_MF_AUTH_KEY_A, trailer_block,
                       &key_a, &uid)
      != StatusCode::STATUS_OK)
    return 0;
  byte size = buffer.size();
  if (MIFARE_Write(block, buffer.data(), (byte) size)
      != StatusCode::STATUS_OK) {
    stop_comm();
    return 0;
  }
  stop_comm();
  return size;
}

int SimpleMFRC522::write_no_block(const std::span<byte> buffer) {
  std::span<byte> cur_view;
  int             bytes{ 0 };
  for (int i = 0, j = 0; i < buffer.size(); i += block_size, ++j) {
    cur_view = buffer.subspan(i, block_size);
    bytes += write_block(BLOCK_ADDRS[j], cur_view);
  }
  return bytes;
}

int SimpleMFRC522::write(const std::string* const str) {
  return write_no_block({ (byte*) str->data(), str->size() });
}

void SimpleMFRC522::stop_comm() {
  PICC_HaltA();
  PCD_StopCrypto1();
}
} // namespace mfrc522
