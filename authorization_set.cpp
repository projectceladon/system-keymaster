/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include <assert.h>

#include "authorization_set.h"

namespace keymaster {

static inline bool is_blob_tag(keymaster_tag_t tag) {
    return (keymaster_tag_get_type(tag) == KM_BYTES || keymaster_tag_get_type(tag) == KM_BIGNUM);
}

const size_t STARTING_ELEMS_CAPACITY = 8;

AuthorizationSet::AuthorizationSet(const AuthorizationSet& set)
    : elems_(NULL), indirect_data_(NULL) {
    elems_ = new keymaster_key_param_t[set.elems_size_];
    if (elems_ == NULL) {
        error_ = ALLOCATION_FAILURE;
        return;
    }
    memcpy(elems_, set.elems_, set.elems_size_ * sizeof(keymaster_key_param_t));
    elems_size_ = set.elems_size_;
    elems_capacity_ = elems_size_;

    if (set.indirect_data_ == NULL) {
        indirect_data_ = NULL;
        indirect_data_size_ = 0;
        indirect_data_capacity_ = 0;
    } else {
        indirect_data_ = new uint8_t[set.indirect_data_size_];
        if (indirect_data_ == NULL) {
            error_ = ALLOCATION_FAILURE;
            return;
        }
        memcpy(indirect_data_, set.indirect_data_, set.indirect_data_size_);
        for (size_t i = 0; i < elems_size_; ++i) {
            if (is_blob_tag(elems_[i].tag))
                elems_[i].blob.data = indirect_data_ + (elems_[i].blob.data - set.indirect_data_);
        }

        indirect_data_size_ = set.indirect_data_size_;
        indirect_data_capacity_ = indirect_data_size_;
    }
    error_ = OK;
}

AuthorizationSet::~AuthorizationSet() {
    FreeData();
}

bool AuthorizationSet::Reinitialize(const keymaster_key_param_t* elems, const size_t count) {
    FreeData();

    elems_size_ = count;
    elems_capacity_ = count;
    indirect_data_size_ = ComputeIndirectDataSize(elems, count);
    indirect_data_capacity_ = indirect_data_size_;
    error_ = OK;

    indirect_data_ = new uint8_t[indirect_data_size_];
    elems_ = new keymaster_key_param_t[elems_size_];
    if (indirect_data_ == NULL || elems_ == NULL) {
        set_invalid(ALLOCATION_FAILURE);
        return false;
    }

    memcpy(elems_, elems, sizeof(keymaster_key_param_t) * elems_size_);
    CopyIndirectData();
    return true;
}

void AuthorizationSet::set_invalid(Error error) {
    error_ = error;
    FreeData();
}

int AuthorizationSet::find(keymaster_tag_t tag, int begin) const {
    int i = ++begin;
    while (i < (int)elems_size_ && elems_[i].tag != tag)
        ++i;
    if (i == (int)elems_size_)
        return -1;
    else
        return i;
}

keymaster_key_param_t empty;

keymaster_key_param_t AuthorizationSet::operator[](int at) const {
    if (at < (int)elems_size_) {
        return elems_[at];
    }
    memset(&empty, 0, sizeof(empty));
    return empty;
}

bool AuthorizationSet::push_back(keymaster_key_param_t elem) {
    if (elems_size_ >= elems_capacity_) {
        size_t new_capacity = elems_capacity_ ? elems_capacity_ * 2 : STARTING_ELEMS_CAPACITY;
        keymaster_key_param_t* new_elems = new keymaster_key_param_t[new_capacity];
        if (new_elems == NULL) {
            set_invalid(ALLOCATION_FAILURE);
            return false;
        }
        memcpy(new_elems, elems_, sizeof(*elems_) * elems_size_);
        delete[] elems_;
        elems_ = new_elems;
        elems_capacity_ = new_capacity;
    }

    if (is_blob_tag(elem.tag)) {
        if (indirect_data_capacity_ - indirect_data_size_ < elem.blob.data_length) {
            size_t new_capacity = 2 * (indirect_data_capacity_ + elem.blob.data_length);
            uint8_t* new_data = new uint8_t[new_capacity];
            if (new_data == false) {
                set_invalid(ALLOCATION_FAILURE);
                return false;
            }
            memcpy(new_data, indirect_data_, indirect_data_size_);
            // Fix up the data pointers to point into the new region.
            for (size_t i = 0; i < elems_size_; ++i) {
                if (is_blob_tag(elems_[i].tag))
                    elems_[i].blob.data = new_data + (elems_[i].blob.data - indirect_data_);
            }
            delete[] indirect_data_;
            indirect_data_ = new_data;
            indirect_data_capacity_ = new_capacity;
        }

        memcpy(indirect_data_ + indirect_data_size_, elem.blob.data, elem.blob.data_length);
        elem.blob.data = indirect_data_ + indirect_data_size_;
        indirect_data_size_ += elem.blob.data_length;
    }

    elems_[elems_size_++] = elem;
    return true;
}

static size_t serialized_size(const keymaster_key_param_t& param) {
    switch (keymaster_tag_get_type(param.tag)) {
    case KM_INVALID:
    default:
        return sizeof(uint32_t);
    case KM_ENUM:
    case KM_ENUM_REP:
    case KM_INT:
    case KM_INT_REP:
        return sizeof(uint32_t) * 2;
    case KM_LONG:
    case KM_DATE:
        return sizeof(uint32_t) + sizeof(uint64_t);
    case KM_BOOL:
        return sizeof(uint32_t) + 1;
        break;
    case KM_BIGNUM:
    case KM_BYTES:
        return sizeof(uint32_t) * 3;
    }
}

static uint8_t* serialize(const keymaster_key_param_t& param, uint8_t* buf, const uint8_t* end,
                          const uint8_t* indirect_base) {
    buf = append_to_buf(buf, end, static_cast<uint32_t>(param.tag));
    switch (keymaster_tag_get_type(param.tag)) {
    case KM_INVALID:
        break;
    case KM_ENUM:
    case KM_ENUM_REP:
        buf = append_to_buf(buf, end, param.enumerated);
        break;
    case KM_INT:
    case KM_INT_REP:
        buf = append_to_buf(buf, end, param.integer);
        break;
    case KM_LONG:
        buf = append_to_buf(buf, end, param.long_integer);
        break;
    case KM_DATE:
        buf = append_to_buf(buf, end, param.date_time);
        break;
    case KM_BOOL:
        if (buf < end)
            *buf = static_cast<uint8_t>(param.boolean);
        buf++;
        break;
    case KM_BIGNUM:
    case KM_BYTES:
        buf = append_to_buf(buf, end, static_cast<uint32_t>(param.blob.data_length));
        buf = append_to_buf(buf, end, static_cast<uint32_t>(param.blob.data - indirect_base));
        break;
    }
    return buf;
}

static bool deserialize(keymaster_key_param_t* param, const uint8_t** buf, const uint8_t* end,
                        const uint8_t* indirect_base, const uint8_t* indirect_end) {
    uint32_t tag_val;
    if (!copy_from_buf(buf, end, &tag_val))
        return false;
    param->tag = static_cast<keymaster_tag_t>(tag_val);

    switch (keymaster_tag_get_type(param->tag)) {
    default:
    case KM_INVALID:
        return false;
    case KM_ENUM:
    case KM_ENUM_REP:
        return copy_from_buf(buf, end, &param->enumerated);
    case KM_INT:
    case KM_INT_REP:
        return copy_from_buf(buf, end, &param->integer);
    case KM_LONG:
        return copy_from_buf(buf, end, &param->long_integer);
    case KM_DATE:
        return copy_from_buf(buf, end, &param->date_time);
        break;
    case KM_BOOL:
        if (*buf < end) {
            param->boolean = static_cast<bool>(**buf);
            (*buf)++;
            return true;
        }
        return false;

    case KM_BIGNUM:
    case KM_BYTES: {
        uint32_t length;
        uint32_t offset;
        if (!copy_from_buf(buf, end, &length) || !copy_from_buf(buf, end, &offset))
            return false;
        if (static_cast<ptrdiff_t>(offset) > indirect_end - indirect_base ||
            static_cast<ptrdiff_t>(offset + length) > indirect_end - indirect_base)
            return false;
        param->blob.data_length = length;
        param->blob.data = indirect_base + offset;
        return true;
    }
    }
}

size_t AuthorizationSet::SerializedSizeOfElements() const {
    size_t size = 0;
    for (size_t i = 0; i < elems_size_; ++i) {
        size += serialized_size(elems_[i]);
    }
    return size;
}

size_t AuthorizationSet::SerializedSize() const {
    return sizeof(uint32_t) +           // Size of indirect_data_
           indirect_data_size_ +        // indirect_data_
           sizeof(uint32_t) +           // Number of elems_
           sizeof(uint32_t) +           // Size of elems_
           SerializedSizeOfElements();  // elems_
}

uint8_t* AuthorizationSet::Serialize(uint8_t* buf, const uint8_t* end) const {
    buf = append_size_and_data_to_buf(buf, end, indirect_data_, indirect_data_size_);
    buf = append_to_buf(buf, end, static_cast<uint32_t>(elems_size_));
    buf = append_to_buf(buf, end, static_cast<uint32_t>(SerializedSizeOfElements()));
    for (size_t i = 0; i < elems_size_; ++i) {
        buf = serialize(elems_[i], buf, end, indirect_data_);
    }
    return buf;
}

bool AuthorizationSet::Deserialize(const uint8_t** buf, const uint8_t* end) {
    FreeData();

    uint32_t elements_count;
    uint32_t elements_size;
    if (!copy_size_and_data_from_buf(buf, end, &indirect_data_size_, &indirect_data_) ||
        !copy_from_buf(buf, end, &elements_count) || !copy_from_buf(buf, end, &elements_size)) {
        set_invalid(MALFORMED_DATA);
        return false;
    }

    // Note that the following validation of elements_count is weak, but it prevents allocation of
    // elems_ arrays which are clearly too large to be reasonable.
    if (elements_size > end - *buf || elements_count * sizeof(uint32_t) > elements_size) {
        set_invalid(MALFORMED_DATA);
        return false;
    }

    elems_ = new keymaster_key_param_t[elements_count];
    if (elems_ == NULL) {
        set_invalid(ALLOCATION_FAILURE);
        return false;
    }

    uint8_t* indirect_end = indirect_data_ + indirect_data_size_;
    const uint8_t* elements_end = *buf + elements_size;
    for (size_t i = 0; i < elements_count; ++i) {
        if (!deserialize(elems_ + i, buf, elements_end, indirect_data_, indirect_end)) {
            set_invalid(MALFORMED_DATA);
            return false;
        }
    }

    if (indirect_data_size_ != ComputeIndirectDataSize(elems_, elements_count)) {
        set_invalid(MALFORMED_DATA);
        return false;
    }

    elems_size_ = elements_count;
    elems_capacity_ = elements_count;
    indirect_data_capacity_ = indirect_data_size_;
    error_ = OK;

    return true;
}

void AuthorizationSet::FreeData() {
    if (elems_ != NULL)
        memset(elems_, 0, elems_size_ * sizeof(keymaster_key_param_t));
    if (indirect_data_ != NULL)
        memset(indirect_data_, 0, indirect_data_size_);

    delete[] elems_;
    delete[] indirect_data_;

    elems_ = NULL;
    indirect_data_ = NULL;
    elems_size_ = 0;
    elems_capacity_ = 0;
    indirect_data_size_ = 0;
    indirect_data_capacity_ = 0;
}

/* static */
size_t AuthorizationSet::ComputeIndirectDataSize(const keymaster_key_param_t* elems, size_t count) {
    size_t size = 0;
    for (size_t i = 0; i < count; ++i) {
        if (is_blob_tag(elems[i].tag)) {
            size += elems[i].blob.data_length;
        }
    }
    return size;
}

void AuthorizationSet::CopyIndirectData() {
    memset(indirect_data_, 0, indirect_data_size_);

    uint8_t* indirect_data_pos = indirect_data_;
    for (size_t i = 0; i < elems_size_; ++i) {
        assert(indirect_data_pos <= indirect_data_ + indirect_data_size_);
        if (is_blob_tag(elems_[i].tag)) {
            memcpy(indirect_data_pos, elems_[i].blob.data, elems_[i].blob.data_length);
            elems_[i].blob.data = indirect_data_pos;
            indirect_data_pos += elems_[i].blob.data_length;
        }
    }
    assert(indirect_data_pos == indirect_data_ + indirect_data_size_);
}

bool AuthorizationSet::GetTagValueEnum(keymaster_tag_t tag, uint32_t* val) const {
    int pos = find(tag);
    if (pos == -1) {
        return false;
    }
    *val = (*this)[pos].enumerated;
    return true;
}

bool AuthorizationSet::GetTagValueEnumRep(keymaster_tag_t tag, size_t instance,
                                          uint32_t* val) const {
    size_t count = 0;
    int pos = -1;
    while (count <= instance) {
        pos = find(tag, pos);
        if (pos == -1) {
            return false;
        }
        ++count;
    }
    *val = (*this)[pos].enumerated;
    return true;
}

bool AuthorizationSet::GetTagValueInt(keymaster_tag_t tag, uint32_t* val) const {
    int pos = find(tag);
    if (pos == -1) {
        return false;
    }
    *val = (*this)[pos].integer;
    return true;
}

bool AuthorizationSet::GetTagValueIntRep(keymaster_tag_t tag, size_t instance,
                                         uint32_t* val) const {
    size_t count = 0;
    int pos = -1;
    while (count <= instance) {
        pos = find(tag, pos);
        if (pos == -1) {
            return false;
        }
        ++count;
    }
    *val = (*this)[pos].integer;
    return true;
}

bool AuthorizationSet::GetTagValueLong(keymaster_tag_t tag, uint64_t* val) const {
    int pos = find(tag);
    if (pos == -1) {
        return false;
    }
    *val = (*this)[pos].long_integer;
    return true;
}

bool AuthorizationSet::GetTagValueDate(keymaster_tag_t tag, uint64_t* val) const {
    int pos = find(tag);
    if (pos == -1) {
        return false;
    }
    *val = (*this)[pos].date_time;
    return true;
}

bool AuthorizationSet::GetTagValueBlob(keymaster_tag_t tag, keymaster_blob_t* val) const {
    int pos = find(tag);
    if (pos == -1) {
        return false;
    }
    *val = (*this)[pos].blob;
    return true;
}

}  // namespace keymaster
