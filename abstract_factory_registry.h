/*
 * Copyright 2014 The Android Open Source Project
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

#ifndef SYSTEM_KEYMASTER_REGISTRY_H_
#define SYSTEM_KEYMASTER_REGISTRY_H_

#include <assert.h>
#include <string.h>

#include <UniquePtr.h>

#include <keymaster/google_keymaster_utils.h>

namespace keymaster {

template <typename AbstractFactoryType, typename ConcreteFactoryType> class FactoryRegistration;
static const size_t DEFAULT_REGISTRY_CAPACITY = 8;

/**
 * A registry of abstract factories that maps keys to concrete subtypes of the specified abstract
 * factory type.  Specific concrete types can be looked up by key using Get(), or all can be
 * retrived with GetAll().  Note that the registry is not designed to handle large numbers of
 * factories (they're stored in an array, which is searched linearly), and it is not recommended to
 * add and remove entries dynamically.
 *
 * To use this registry:
 *
 * 1.  Create an AbstractFactory class.  It must contain:
 *     a.  A typedef "KeyType" that defines the registry key type.
 *     b.  A pure virtual method "registry_key()" that returns KeyType.
 *     c.  A virtual destructor.
 *     d.  Factory methods (likely all pure virtual).
 *
 * 2.  Create one or more concrete subclasses of AbstractFactory.  The concrete factories must have
 *     failure-proof no-argument constructors.  Note that by design it is impossible to register two
 *     factories which return the same value from registry_key().  Attempting to do so will cause
 *     both to be removed.
 *
 * 3.  Define the registry instance pointer using the DEFINE_ABSTRACT_FACTORY_REGISTRY_INSTANCE
 *     macro.
 *
 * 4.  Register each of the concrete factories by creating an instance of
 *     AbstractFactoryRegistry<AbstractFactory>::Registration<ConcreteFactory> for each concrete
 *     factory.  The best way to do this is to create static Registration instances at file scope in
 *     appropriate compilation units.  Their constructors will create and register the concrete
 *     factories during startup and their destructors will clean up during shutdown.  Registration
 *     is not new'able, specifically to discourage dynamic allocation.
 *
 * 5.  At run-time call Get() or GetAll() to retrieve AbstractFactory-typed pointers to the concrete
 *     factories, then use the factories.
 *
 * 6.  (Optional, but recommended) Shortly after startup, use GetAll() and validate that all of the
 *     entries appear to be valid.  In the absence of exceptions, failures will be silent.  In the
 *     presence of exceptions, failures that throw would cause a crash on startup.
 */
template <typename AbstractFactoryType> class AbstractFactoryRegistry {
  public:
    typedef typename AbstractFactoryType::KeyType KeyType;

    /**
     * Get a concrete factory for the specified key type.
     */
    static AbstractFactoryType* Get(const KeyType key) { return instance()->GetFactory(key); }

    /**
     * Get all concrete factories.  The caller does NOT take ownership of the returned array, and
     * must not modify anything in it.
     */
    static const AbstractFactoryType** GetAll(size_t* factory_count) {
        return const_cast<const AbstractFactoryType**>(instance()->GetAllFactories(factory_count));
    }

    /**
     * Return a the number of registered factories.
     */
    static size_t size() { return instance()->num_factories(); }

    /**
     * Registration objects are responsible for creating, registering, de-registering and deleting
     * concrete factory instances.  Operator new is private and unimplemented to prevent dynamic
     * allocation; Registrations must be either stack- or statically-allocated.
     */
    template <typename ConcreteFactoryType> class Registration {
      public:
        Registration() : factory_(new ConcreteFactoryType) {
            AbstractFactoryRegistry::instance()->Register(factory_.get());
        }

        ~Registration() {
            if (instance_ptr)
                instance_ptr->Deregister(factory_.get());
        }

      private:
        void* operator new(size_t);  // Prevent heap allocation
        UniquePtr<ConcreteFactoryType> factory_;
    };

  private:
    template <typename A, typename C> friend class FactoryRegistration;

    static AbstractFactoryRegistry* instance() {
        if (!instance_ptr)
            instance_ptr = new AbstractFactoryRegistry;
        return instance_ptr;
    }

    void Register(AbstractFactoryType* entry);
    void Deregister(AbstractFactoryType* entry);

    AbstractFactoryType* GetFactory(const KeyType key) const;
    AbstractFactoryType** GetAllFactories(size_t* factory_count) const;
    size_t num_factories() const { return size_; }

    AbstractFactoryRegistry()
        : capacity_(DEFAULT_REGISTRY_CAPACITY), size_(0),
          entries_(new AbstractFactoryType* [capacity_]) {}
    ~AbstractFactoryRegistry() {
        assert(this == instance_ptr);
        instance_ptr = 0;
    }

    void DeregisterAll() { delete instance_ptr; }

    size_t capacity_;
    size_t size_;
    UniquePtr<AbstractFactoryType* []> entries_;

#ifdef TESTING_REGISTRY
  public:
#endif  // TESTING_REGISTRY
    static AbstractFactoryRegistry* instance_ptr;
};

/**
 * Helper macro for defining a registry instance.
 */
#define DEFINE_ABSTRACT_FACTORY_REGISTRY_INSTANCE(AbstractFactoryType)                             \
    template <>                                                                                    \
    AbstractFactoryRegistry<AbstractFactoryType>*                                                  \
        AbstractFactoryRegistry<AbstractFactoryType>::instance_ptr = 0

template <typename AbstractFactoryType>
AbstractFactoryType* AbstractFactoryRegistry<AbstractFactoryType>::GetFactory(
    const typename AbstractFactoryType::KeyType key) const {
    for (auto& entry : ArrayWrapper<AbstractFactoryType*>(entries_.get(), size_))
        if (entry->registry_key() == key)
            return entry;
    return NULL;
}

template <typename AbstractFactoryType>
AbstractFactoryType**
AbstractFactoryRegistry<AbstractFactoryType>::GetAllFactories(size_t* factory_count) const {
    *factory_count = size_;
    return entries_.get();
}

template <typename AbstractFactoryType>
void AbstractFactoryRegistry<AbstractFactoryType>::Register(AbstractFactoryType* entry) {
    AbstractFactoryType* tmp = GetFactory(entry->registry_key());
    if (tmp) {
        // Already have one.  Don't add this one and remove the one we have.
        Deregister(tmp);
        return;
    }

    if (size_ == capacity_) {
        size_t new_capacity = capacity_ * 2;
        UniquePtr<AbstractFactoryType* []> new_entries(new AbstractFactoryType* [new_capacity]);
        if (!new_entries.get()) {
            // TODO(swillden): Log an error here.
            return;
        }
        memcpy(new_entries.get(), entries_.get(), sizeof(AbstractFactoryType*) * size_);
        entries_.reset(new_entries.release());
        capacity_ = new_capacity;
    }
    entries_[size_++] = entry;
}

template <typename AbstractFactoryType>
void AbstractFactoryRegistry<AbstractFactoryType>::Deregister(AbstractFactoryType* entry) {
    // Since registration should always occur in reverse order from registration (due to
    // FactoryRegistration not being new'able), entry should be the last in the registry.  We handle
    // the more general case of out-of-order deregistrations in the code, but these assertions will
    // tell us if something is wrong.
    assert(size_ > 0);
    assert(entry->registry_key() == entries_[size_ - 1]->registry_key());

    for (int i = size_ - 1; i >= 0; --i) {
        if (entries_[i]->registry_key() == entry->registry_key()) {
            for (int j = i + 1; j < (int)size_; ++j)
                entries_[j - 1] = entries_[j];
            if (--size_ == 0)
                delete instance_ptr;
            return;
        }
    }
}

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_REGISTRY_H_
