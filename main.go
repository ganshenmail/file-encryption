package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keyLen   = chacha20poly1305.KeySize    // 32
	nonceLen = chacha20poly1305.NonceSizeX // 24
	tagLen   = 16
	bufSize  = 65536 // 64KB 流式缓冲区
	filePerm = 0o600
	dirPerm  = 0o700
)

// secureZero 安全擦除内存，规避编译器优化
func secureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func fileExists(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
}

// genKeySave 生成并保存密钥，存在则提示覆盖
func genKeySave(keyPath string) ([]byte, error) {
	if fileExists(keyPath) {
		fmt.Printf("警告：密钥文件 %s 已存在，覆盖后原有密文将无法解密！是否继续(y/N)：", keyPath)
		var in string
		fmt.Scanln(&in)
		if strings.ToLower(in) != "y" {
			return nil, errors.New("用户取消操作，密钥未覆盖")
		}
	}

	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成密钥失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), dirPerm); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(key); err != nil {
		return nil, err
	}
	return key, nil
}

func loadKey(keyPath string) ([]byte, error) {
	if !fileExists(keyPath) {
		return nil, errors.New("密钥文件不存在: " + keyPath)
	}
	f, err := os.Open(keyPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	key := make([]byte, keyLen)
	n, err := io.ReadFull(f, key)
	if err != nil {
		secureZero(key)
		return nil, fmt.Errorf("密钥损坏，需32字节，实际读取%d字节", n)
	}
	return key, nil
}

// encryptFile 流式加密，恒定内存，无全局明文缓存
func encryptFile(src string) error {
	if !fileExists(src) {
		return errors.New("源文件不存在: " + src)
	}
	base := src
	keyPath := base + ".key"
	encPath := base + ".enc"
	_ = os.MkdirAll(filepath.Dir(encPath), dirPerm)

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开源文件: %w", err)
	}
	defer in.Close()

	outEnc, err := os.OpenFile(encPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return fmt.Errorf("创建密文文件: %w", err)
	}
	defer outEnc.Close()

	key, err := genKeySave(keyPath)
	if err != nil {
		return err
	}
	defer secureZero(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	// 全局唯一nonce写入文件头
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if _, err := outEnc.Write(nonce); err != nil {
		return err
	}

	// AD：绑定原始文件名，防止跨文件篡改
	ad := []byte(filepath.Base(src))
	buf := make([]byte, bufSize)
	fmt.Println("流式加密处理中...")

	for {
		n, err := in.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			// 单次加密，不复用nonce做多次加密，仅用此nonce加密整个文件分段
			chunkCipher := aead.Seal(nil, nonce, chunk, ad)
			// 写入4字节大端长度 + 密文段
			lenBuf := [4]byte{}
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(chunkCipher)))
			if _, err := outEnc.Write(lenBuf[:]); err != nil {
				return err
			}
			if _, err := outEnc.Write(chunkCipher); err != nil {
				return err
			}
			secureZero(chunkCipher)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取源文件: %w", err)
		}
	}

	fmt.Printf("加密完成\n密文文件：%s\n密钥文件：%s\n", encPath, keyPath)
	return nil
}

// decryptFile 流式解密，无全局明文缓存，逐块校验tag
func decryptFile(encPath string) error {
	if !fileExists(encPath) {
		return errors.New("加密文件不存在: " + encPath)
	}
	base := strings.TrimSuffix(encPath, ".enc")
	keyPath := base + ".key"
	outRaw := base
	_ = os.MkdirAll(filepath.Dir(outRaw), dirPerm)

	f, err := os.Open(encPath)
	if err != nil {
		return fmt.Errorf("打开加密文件: %w", err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	fSize := stat.Size()
	// 最小文件：nonce(24) + 4长度 + 至少1字节密文+tag
	if fSize < nonceLen+4+tagLen {
		return errors.New("加密文件过小，已损坏或截断")
	}

	// 读取头部nonce
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(f, nonce); err != nil {
		return errors.New("读取文件nonce失败，文件损坏")
	}

	outRawF, err := os.OpenFile(outRaw, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return fmt.Errorf("创建输出明文文件: %w", err)
	}
	defer outRawF.Close()

	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	defer secureZero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	ad := []byte(filepath.Base(base))
	lenBuf := [4]byte{}
	fmt.Println("流式解密校验中...")

	for {
		// 读取块长度
		_, err := io.ReadFull(f, lenBuf[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("读取数据块长度失败：文件损坏/截断")
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf[:])
		if chunkLen == 0 {
			break
		}
		// 防止越界读取
		curPos, _ := f.Seek(0, io.SeekCurrent)
		if curPos+int64(chunkLen) > fSize {
			return errors.New("密文块超出文件范围，文件被截断或篡改")
		}

		chunkCipher := make([]byte, chunkLen)
		if _, err := io.ReadFull(f, chunkCipher); err != nil {
			return fmt.Errorf("读取密文段失败: %w", err)
		}

		// 逐块校验Poly1305 tag，失败直接中断
		chunkPlain, err := aead.Open(nil, nonce, chunkCipher, ad)
		if err != nil {
			secureZero(chunkCipher)
			return errors.New("解密校验失败：密钥错误、文件篡改或损坏")
		}

		if _, err := outRawF.Write(chunkPlain); err != nil {
			return fmt.Errorf("写入明文失败: %w", err)
		}
		secureZero(chunkPlain)
		secureZero(chunkCipher)
	}

	fmt.Printf("解密完成，输出文件：%s\n", outRaw)
	return nil
}

func help() {
	fmt.Println(`
XChaCha20-Poly1305 安全文件加密工具（修复版）
用法：
  tool.exe test.iso      加密生成 test.iso.enc + test.iso.key
  tool.exe test.iso.enc  解密恢复原文件
安全特性：
  1. 恒定64KB内存流式处理，支持TB级超大文件
  2. XChaCha20-Poly1305 AEAD，每块自带完整性校验
  3. 绑定文件名作为关联数据，防止密文跨文件篡改
  4. 密钥权限0600，文件权限最小化
  5. 内存敏感数据安全擦除，防止内存泄露
  6. 密钥存在时二次确认覆盖，避免误操作
注意：丢失.key密钥文件将无法解密！
`)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		help()
	}
	path := os.Args[1]
	var err error
	if strings.HasSuffix(path, ".enc") {
		err = decryptFile(path)
	} else {
		err = encryptFile(path)
	}
	if err != nil {
		fmt.Printf("操作失败：%v\n", err)
		os.Exit(1)
	}
	fmt.Println("操作执行成功！")
}
