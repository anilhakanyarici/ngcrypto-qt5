#include "rfc2898generator.h"

#include "hmac.h"

struct Rfc2898Generator::pimpl
{
    QByteArray _buffer;
    QByteArray _salt;
    HMAC _hmac;
    QByteArray _password;
    uint _iterations;
    uint _block;
    int _startIndex;
    int _endIndex;
    DerivationFunction _derFunc;

    QByteArray deriveBlock()
    {
        QByteArray array(reinterpret_cast<char*>(&this->_block), 4);
        for(int i = 0; i < 2; ++i){
            char t = array[3 - i];
            array[3 - i] = array[i];
            array[i] = t;
        }

        this->_hmac.addData(this->_salt);
        this->_hmac.addData(array);
        QByteArray hashValue = this->_hmac.result();
        this->_hmac.reset();
        QByteArray array2(hashValue);
        int num = 2;
        if (this->_derFunc == DerivationFunction::PBKDF1)
        {
            while ((long)num <= (long)((ulong)this->_iterations))
            {
                this->_hmac.addData(hashValue);
                this->_hmac.addData(array2);
                hashValue = this->_hmac.result();
                array2 = QByteArray(hashValue);
                this->_hmac.reset();
                num++;
            }
        }
        else if (this->_derFunc == DerivationFunction::PBKDF2)
        {
            while ((long)num <= (long)((ulong)this->_iterations))
            {
                this->_hmac.addData(hashValue);
                hashValue = this->_hmac.result();
                for (int i = 0; i < 20; i++)
                {
                    array2[i] = array2[i] ^ hashValue[i];
                }
                this->_hmac.reset();
                num++;
            }
        }
        this->_block += 1u;
        return array2;
    }
};

Rfc2898Generator::Rfc2898Generator(const QString &password, ulong salt, uint iterations, Rfc2898Generator::DerivationFunction function)
    : Rfc2898Generator(password.toUtf8(), salt, iterations, function)
{

}

Rfc2898Generator::Rfc2898Generator(const QByteArray &password, ulong salt, uint iterations, Rfc2898Generator::DerivationFunction function)
{
    this->_pimpl = QSharedPointer<pimpl>(new pimpl);
    this->_pimpl->_salt = QByteArray(reinterpret_cast<char*>(&salt), 8);
    this->_pimpl->_iterations = iterations;
    this->_pimpl->_password = password;
    this->_pimpl->_hmac = HMAC(QCryptographicHash::Sha1, password);
    this->_pimpl->_derFunc = function;

    this->reset();
}

ulong Rfc2898Generator::salt() const
{
    return *reinterpret_cast<ulong*>(this->_pimpl->_salt.data());
}

void Rfc2898Generator::setSalt(ulong salt)
{
    this->_pimpl->_salt = QByteArray(reinterpret_cast<char*>(&salt), 8);
}

uint Rfc2898Generator::iteration() const
{
    return this->_pimpl->_iterations;
}

void Rfc2898Generator::setIteration(uint iter)
{
    this->_pimpl->_iterations = iter;
}

QByteArray Rfc2898Generator::generate(int cb)
{
    if (cb <= 0)
        return QByteArray();
    QByteArray array(cb, '\0');
    int i = 0;
    int num = this->_pimpl->_endIndex - this->_pimpl->_startIndex;
    if (num > 0)
    {
        if (cb < num)
        {
            ::memcpy(array.data(), this->_pimpl->_buffer.data() + this->_pimpl->_startIndex, cb);
            this->_pimpl->_startIndex += cb;
            return array;
        }
        ::memcpy(array.data(), this->_pimpl->_buffer.data() + this->_pimpl->_startIndex, num);
        this->_pimpl->_startIndex = (this->_pimpl->_endIndex = 0);
        i += num;
    }
    while (i < cb)
    {
        QByteArray src = this->_pimpl->deriveBlock();
        int num2 = cb - i;
        if (num2 <= 20)
        {
            ::memcpy(array.data() + i, src.data(), num2);
            i += num2;
            ::memcpy(this->_pimpl->_buffer.data() + this->_pimpl->_startIndex, src.data() + num2, 20 - num2);
            this->_pimpl->_endIndex += 20 - num2;
            return array;
        }
        ::memcpy(array.data() + i, src.data(), 20);
        i += 20;
    }
    return array;
}

void Rfc2898Generator::reset()
{
    this->_pimpl->_buffer.clear();
    this->_pimpl->_buffer = QByteArray(20, '\0');
    this->_pimpl->_block = 1u;
    this->_pimpl->_startIndex = (this->_pimpl->_endIndex = 0);
}

