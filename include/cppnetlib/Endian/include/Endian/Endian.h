#ifndef ENDIAN_H_
#define ENDIAN_H_

#include <cstdint>
#include <type_traits>

class Endian {
public:
    // TODO: Add another endians (ARM uses bi-endian .. for example)
    enum class Type { Little, Big, Unknown };

    static Type getNative() { return getInstance().mNativeEndian; }

    template <typename T>
    static T convertToNative(const T& value, const Type sourceEndian) {
        return getInstance().convertToNativeImpl(value, sourceEndian);
    }

    template <typename T>
    static T convertNativeTo(const T& value, const Type targetEndian) {
        return getInstance().convertNativeToImpl(value, targetEndian);
    }

private:
    Endian()
        : mNativeEndian(findOutNativeEndian()) {}

    static const Endian& getInstance() {
        static Endian instance;
        return instance;
    }

    static Type findOutNativeEndian() {
        const uint32_t testValue = 0x00000001;
        if (*(reinterpret_cast<const char*>(&testValue) + 3) & 0x01) {
            return Type::Big;
        } else if (*(reinterpret_cast<const char*>(&testValue)) & 0x01) {
            return Type::Little;
        } else {
            return Type::Unknown;
        }
    }

    template <typename T,
              typename std::enable_if<std::is_trivially_default_constructible<T>::value, char>::type = 0>
    static T inverseEndian(const T& value) {
        const std::size_t typeSize = sizeof(T);

        const char* ptrSrc = reinterpret_cast<const char*>(&value);

        T result;
        char* ptrDst = reinterpret_cast<char*>(&result);

        for (std::size_t i = 0; i < typeSize; ++i) {
            ptrDst[i] = ptrSrc[typeSize - 1 - i];
        }

        return result;
    }

    template <typename T>
    static T convertToNativeImpl(const T& value, const Type sourceEndian) {
        if (sourceEndian == getNative()) {
            return value;
        } else {
            return inverseEndian(value);
        }
    }

    template <typename T>
    static T convertNativeToImpl(const T& value, const Type targetEndian) {
        return convertToNativeImpl(value, targetEndian);
    }

    Type mNativeEndian;
};

#endif