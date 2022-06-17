#pragma once

#include "mfrc522/MFRC522.hpp"

#include <stdint.h>
#include <string>
#include <vector>
#include <span>

namespace mfrc522 {
std::string byte_to_hex(byte b);

class SimpleMFRC522 : private MFRC522 {
private:
  std::vector<mfrc522::byte> BLOCK_ADDRS;

  static const int block_size;

  MIFARE_Key key_a;
  MIFARE_Key key_b;

public:
  SimpleMFRC522(int ss_pin = 24, int rst_pin = 25, int spi_channel = 0);


  Uid*     getUid();
  uint64_t uid_to_num(const Uid* const uid);

  bool is_available();
  Uid* select_card();

  int read_block(mfrc522::byte block, std::span<byte>& buffer);
  int read(std::string* str);
  int write_block(mfrc522::byte block, const std::span<byte>& buffer);
  int write(const std::string* const str);

  void stop_comm();
};
} // namespace mfrc522
