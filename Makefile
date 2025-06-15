CC = gcc
CFLAGS = -static -o3 -w -I"./include/third_paryt" -DCURL_STATICLIB -DNGHTTP2_STATICLIB -DNGHTTP3_STATICLIB
LDFLAGS = -static -o3 -L"./lib"

TARGET = CBeaon.exe

SRC_DIR = src
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:.c=.o)

LIBS = -lcurl -lz -lwldap32 -lws2_32 -lbcrypt -ladvapi32 -lcrypt32 \
       -lssh2 -lws2_32 -lcrypt32 -lbcrypt -lz \
       -lbrotlidec -lbrotlicommon -lzstd -lnghttp2 -lnghttp3 \
       -lpsl -lunistring -lws2_32 -liconv -lidn2 -liconv \
       -lunistring -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	del .\src\*.o

.PHONY: all clean
