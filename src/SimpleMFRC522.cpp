#include "mfrc522/SimpleMFRC522.hpp"
#include "mfrc522/MFRC522.hpp"
#include <algorithm>
#include <stdint.h>
#include <string>

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

const int SimpleMFRC522::block_size{ 16 };

SimpleMFRC522::SimpleMFRC522(int ss_pin, int rst_pin, int spi_channel)
    : MFRC522{ ss_pin, rst_pin, spi_channel }
    , BLOCK_ADDRS{} {
  PCD_Init();

  key_a.keyByte[0] = 0xFF;
  key_a.keyByte[1] = 0xFF;
  key_a.keyByte[2] = 0xFF;
  key_a.keyByte[3] = 0xFF;
  key_a.keyByte[4] = 0xFF;
  key_a.keyByte[5] = 0xFF;

  key_b.keyByte[0] = 0xFF;
  key_b.keyByte[1] = 0xFF;
  key_b.keyByte[2] = 0xFF;
  key_b.keyByte[3] = 0xFF;
  key_b.keyByte[4] = 0xFF;
  key_b.keyByte[5] = 0xFF;

  for (byte i = 0; i < 64; ++i) {
    if (!(i < 8 || i == i + (4 - i % 4) - 1)) {
      BLOCK_ADDRS.push_back(i);
    }
  }
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
    byte buffer[2];
    byte size{ 2 };
    PICC_WakeupA(buffer, &size);
    if (PICC_ReadCardSerial() == StatusCode::STATUS_OK) {
      break;
    }
    // PICC_IsNewCardPresent();
  }
  if (i == 3) {
    uid = Uid{};
    return nullptr;
  }
  return &uid;
}

int SimpleMFRC522::read_block(mfrc522::byte block, std::span<byte>& buffer) {
  if (!select_card())
    return 0;
  int trailer_block = block + (4 - block % 4) - 1;
  if (PCD_Authenticate(PICC_Command::PICC_CMD_MF_AUTH_KEY_A, trailer_block,
                       &key_a, &uid)
      != StatusCode::STATUS_OK)
    return 0;
  byte size = buffer.size();
  if (MIFARE_Read(block, buffer.data(), (mfrc522::byte*) &size)
      != StatusCode::STATUS_OK) {
    stop_comm();
    return 0;
  }
  stop_comm();
  return size;
}

int SimpleMFRC522::read(std::string* str) {
  str->clear();
  for (auto x : BLOCK_ADDRS) {
    mfrc522::byte buffer[block_size + 2]{};
    size_t        size = block_size + 2;
    if (read_block(x, buffer, size)) {
      for (int i = 0; i < block_size; ++i) {
        (*str) += (char) buffer[i];
      }
    } else {
      break;
    }
  }
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

int SimpleMFRC522::write_block(mfrc522::byte          block,
                               const std::span<byte>& buffer) {
  if ((block + 1) % 4 == 0)
    return 0;
  if (!select_card())
    return 0;
  int trailer_block = block + (4 - block % 4) - 1;
  if (PCD_Authenticate(PICC_Command::PICC_CMD_MF_AUTH_KEY_A, trailer_block,
                       &key_a, &uid)
      != StatusCode::STATUS_OK)
    return 0;
  byte size = buffer.size();
  if (MIFARE_Write(block, buffer.data(), (mfrc522::byte) size)
      != StatusCode::STATUS_OK) {
    stop_comm();
    return 0;
  }
  stop_comm();
  return size;
}

int SimpleMFRC522::write(const std::string* const str) {
  return 0;
}

void SimpleMFRC522::stop_comm() {
  // PICC_HaltA();
  PCD_StopCrypto1();
}

} // namespace mfrc522
