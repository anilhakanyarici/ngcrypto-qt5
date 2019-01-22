#ifndef AES_H
#define AES_H

#include <QByteArray>
#include <QSharedPointer>

enum PaddingMode { PADDINGMODE_ANSIX923 = 4, PADDINGMODE_ISO10126, PADDINGMODE_None = 1, PADDINGMODE_PKCS7, PADDINGMODE_Zeros };
enum CipherMode { CIPHERMODE_CBC = 1, CIPHERMODE_CFB = 4, CIPHERMODE_CTS, CIPHERMODE_ECB = 2, CIPHERMODE_OFB };

class AES
{
    struct pimpl;
    QSharedPointer<pimpl> _pimpl;

public:
    AES(int bit_size = 128);

    const QByteArray &key() const;
    bool setKey(const QByteArray &key);
    const QByteArray &IV() const;
    bool setIV(const QByteArray &iv);
    PaddingMode paddingMode() const;
    void setPaddingMode(PaddingMode mode);
    CipherMode cipherMode() const;
    void setCipherMode(CipherMode mode);

    void generateKey();
    void generateIV();

    QByteArray encrypt(const QByteArray &input) const;
    int encrypt(const QByteArray &input, QByteArray &output) const;
    QByteArray decrypt(const QByteArray &input) const;
    int decrypt(const QByteArray &input, QByteArray &output) const;
};

#endif // AES_H
