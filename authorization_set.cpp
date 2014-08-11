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
        indirect_data_size_ = set.indirect_data_size_;
        indirect_data_capacity_ = indirect_data_size_;
    }
    error_ = OK;
}

AuthorizationSet::~AuthorizationSet() { FreeData(); }

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
    ConvertPointersToOffsets(elems_, elems_size_, indirect_data_);
    return true;
}

void AuthorizationSet::set_invalid(Error error) {
    error_ = error;
    FreeData();
}

int AuthorizationSet::find(keymaster_tag_t tag, int begin) const {
    int i = ++begin;
    for (; i < (int)elems_size_ && elems_[i].tag != tag; ++i) {
    }
    if (i == (int)elems_size_)
        return -1;
    else
        return i;
}

keymaster_key_param_t empty;

keymaster_key_param_t AuthorizationSet::operator[](int at) const {
    if (at < (int)elems_size_) {
        keymaster_key_param_t retval = elems_[at];
        if (is_blob_tag(elems_[at].tag)) {
            // Data "pointer" is actually an offset.  Convert it to a pointer.
            retval.blob.data = indirect_data_ + reinterpret_cast<ptrdiff_t>(retval.blob.data);
        }
        return retval;
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
            delete[] indirect_data_;
            indirect_data_ = new_data;
            indirect_data_capacity_ = new_capacity;
        }

        memcpy(indirect_data_ + indirect_data_size_, elem.blob.data, elem.blob.data_length);
        elem.blob.data = reinterpret_cast<uint8_t*>(indirect_data_size_);
        indirect_data_size_ += elem.blob.data_length;
    }

    elems_[elems_size_++] = elem;
    return true;
}

size_t AuthorizationSet::SerializedSize() const {
    return sizeof(uint32_t) +                 // Length of elems_
           (sizeof(*elems_) * elems_size_) +  // elems_
           sizeof(uint32_t) +                 // Length of indirect data
           indirect_data_size_;               // Indirect data
}

uint8_t* AuthorizationSet::Serialize(uint8_t* serialized_set, const uint8_t* end) const {
    serialized_set =
        append_size_and_data_to_buf(serialized_set, end, elems_, elems_size_ * sizeof(*elems_));
    return append_size_and_data_to_buf(serialized_set, end, indirect_data_, indirect_data_size_);
}

bool AuthorizationSet::Deserialize(const uint8_t** buf, const uint8_t* end) {
    FreeData();

    uint32_t elems_buf_size;
    if (!copy_from_buf(buf, end, &elems_buf_size) ||
        (elems_buf_size % sizeof(keymaster_key_param_t)) != 0 || end < (*buf + elems_buf_size)) {
        set_invalid(MALFORMED_DATA);
        return false;
    }

    elems_ = new keymaster_key_param_t[elems_buf_size / sizeof(keymaster_key_param_t)];
    if (elems_ == NULL) {
        set_invalid(ALLOCATION_FAILURE);
        return false;
    }
    memcpy(elems_, *buf, elems_buf_size);
    *buf += elems_buf_size;

    uint32_t indirect_size;
    if (!copy_from_buf(buf, end, &indirect_size) ||
        indirect_size !=
            ComputeIndirectDataSize(elems_, elems_buf_size / sizeof(keymaster_key_param_t))) {
        set_invalid(MALFORMED_DATA);
        return false;
    }

    indirect_data_ = new uint8_t[indirect_size];
    if (indirect_data_ == NULL) {
        set_invalid(ALLOCATION_FAILURE);
        return false;
    }
    memcpy(indirect_data_, *buf, indirect_size);
    *buf += indirect_size;

    elems_size_ = elems_buf_size / sizeof(keymaster_key_param_t);
    elems_capacity_ = elems_size_;
    indirect_data_size_ = indirect_size;
    indirect_data_capacity_ = indirect_size;
    error_ = OK;

    return CheckIndirectDataOffsets();
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

/* static */
void AuthorizationSet::ConvertPointersToOffsets(keymaster_key_param_t* elems, size_t count,
                                                const uint8_t* indirect_base) {
    for (size_t i = 0; i < count; ++i) {
        if (is_blob_tag(elems[i].tag)) {
            elems[i].blob.data = reinterpret_cast<uint8_t*>(elems[i].blob.data - indirect_base);
        }
    }
}

bool AuthorizationSet::CheckIndirectDataOffsets() {
    // TODO(swillden): Find an efficient way to test for overlaps. Verifying that the total size of
    // the indirect blobs found matches the size of the indirect data buffer and that all of the
    // offsets fall into the correct region precludes most sorts of indirect data table
    // malformation, but it doesn't prevent overlaps which are accompanied by unused regions whose
    // total size exactly offsets the overlaps.
    size_t computed_indirect_data_size = 0;

    for (size_t i = 0; i < elems_size_; ++i) {
        if (is_blob_tag(elems_[i].tag)) {
            computed_indirect_data_size += elems_[i].blob.data_length;
            ptrdiff_t offset = reinterpret_cast<ptrdiff_t>(elems_[i].blob.data);
            if (offset < 0 || offset > (ptrdiff_t)indirect_data_size_ ||
                offset + elems_[i].blob.data_length > indirect_data_size_) {
                set_invalid(BOUNDS_CHECKING_FAILURE);
                return false;
            }
        }
    }

    if (computed_indirect_data_size != indirect_data_size_) {
        set_invalid(MALFORMED_DATA);
        return false;
    }

    return true;
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
