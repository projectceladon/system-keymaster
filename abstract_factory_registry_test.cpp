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

#define TESTING_REGISTRY
#include "abstract_factory_registry.h"

#include <algorithm>

#include <gtest/gtest.h>

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return result;
}

namespace keymaster {

class TestAbstractFactory {
  public:
    virtual ~TestAbstractFactory() {}
    typedef int KeyType;
    virtual KeyType registry_key() const = 0;
};

// For actual applications, the concrete factories will be different types, but for convenience we
// use this template to create a whole family of concrete subtypes.
template <int key> class TestFactory : public TestAbstractFactory {
  public:
    TestAbstractFactory::KeyType registry_key() const { return key; }
};

typedef AbstractFactoryRegistry<TestAbstractFactory> TestRegistry;

DEFINE_ABSTRACT_FACTORY_REGISTRY_INSTANCE(TestAbstractFactory);

#define REGISTER_FACTORY(n) TestRegistry::Registration<TestFactory<n>> registration##n

TEST(RegistryTest, RegisterAndDeregister) {
    // Registry instance hasn't been created.
    EXPECT_TRUE(TestRegistry::instance_ptr == NULL);

    {
        REGISTER_FACTORY(1);

        // Registry instance should have been created.
        EXPECT_FALSE(TestRegistry::instance_ptr == NULL);

        // Registry should contain instance.
        EXPECT_EQ(1, TestRegistry::size());
        ASSERT_TRUE(TestRegistry::Get(1) != NULL);
        EXPECT_EQ(1, TestRegistry::Get(1)->registry_key());

        // Registration goes out of scope here.
    }

    // Registry should have been deleted, and pointer zeroed
    EXPECT_TRUE(TestRegistry::instance_ptr == NULL);
}

TEST(RegistryTest, RegisterAndDeregisterTwo) {
    // Registry instance hasn't been created.
    EXPECT_TRUE(TestRegistry::instance_ptr == NULL);

    {
        REGISTER_FACTORY(1);

        // Registry instance should have been created.
        EXPECT_FALSE(TestRegistry::instance_ptr == NULL);

        // Registry should contain instance.
        EXPECT_EQ(1, TestRegistry::size());
        ASSERT_TRUE(TestRegistry::Get(1) != NULL);
        EXPECT_EQ(1, TestRegistry::Get(1)->registry_key());

        {
            REGISTER_FACTORY(2);

            // Registry should contain both.
            EXPECT_EQ(2, TestRegistry::size());
            ASSERT_TRUE(TestRegistry::Get(1) != NULL);
            ASSERT_TRUE(TestRegistry::Get(2) != NULL);
            EXPECT_EQ(1, TestRegistry::Get(1)->registry_key());
            EXPECT_EQ(2, TestRegistry::Get(2)->registry_key());

            // First registration goes out of scope here.
        }

        // Registry should contain first still.
        EXPECT_EQ(1, TestRegistry::size());
        ASSERT_TRUE(TestRegistry::Get(2) == NULL);
        ASSERT_TRUE(TestRegistry::Get(1) != NULL);
        EXPECT_EQ(1, TestRegistry::Get(1)->registry_key());

        // Second registration goes out of scope here.
    }

    // Registry should have been deleted, and pointer zeroed
    EXPECT_TRUE(TestRegistry::instance_ptr == NULL);
}

TEST(RegistryTest, RegisterAndDeregisterTen) {
    // Registry instance hasn't been created.
    EXPECT_TRUE(TestRegistry::instance_ptr == NULL);

    {
        // Register 10 factories.
        REGISTER_FACTORY(1);
        REGISTER_FACTORY(2);
        REGISTER_FACTORY(3);
        REGISTER_FACTORY(4);
        REGISTER_FACTORY(5);
        REGISTER_FACTORY(6);
        REGISTER_FACTORY(7);
        REGISTER_FACTORY(8);
        REGISTER_FACTORY(9);
        REGISTER_FACTORY(10);

        // Registry instance should have been created.
        EXPECT_FALSE(TestRegistry::instance_ptr == NULL);

        // Registry should contain all 10.
        EXPECT_EQ(10, TestRegistry::size());
        for (int i = 1; i <= 10; ++i) {
            ASSERT_TRUE(TestRegistry::Get(i) != NULL);
            EXPECT_EQ(i, TestRegistry::Get(i)->registry_key());
        }

        // Registrations go out of scope here.
    }

    // Registry should have been deleted, and pointer zeroed
    EXPECT_TRUE(TestRegistry::instance_ptr == NULL);
}

TEST(RegistryTest, DoubleRegister) {
    // Registry instance hasn't been created.
    EXPECT_TRUE(TestRegistry::instance_ptr == NULL);

    // Register a factory;
    TestRegistry::Registration<TestFactory<1>> registration1;
    // Registry instance should have been created.
    EXPECT_FALSE(TestRegistry::instance_ptr == NULL);

    // Registry should contain instance.
    EXPECT_EQ(1, TestRegistry::size());
    ASSERT_TRUE(TestRegistry::Get(1) != NULL);
    EXPECT_EQ(1, TestRegistry::Get(1)->registry_key());

    // Register another with the same key.
    TestRegistry::Registration<TestFactory<1>> registration2;

    // Registry should have been deleted, and pointer zeroed
    EXPECT_TRUE(TestRegistry::instance_ptr == NULL);
}

}  // namespace keymaster
