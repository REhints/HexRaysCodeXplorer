/*
    Simple chooser test to verify IDA SDK 9.2 chooser API
*/

#include "Common.h"
#include <kernwin.hpp>

// Simple test chooser
class SimpleTestChooser : public chooser_t {
private:
    qstrvec_t items;
    
public:
    SimpleTestChooser() : chooser_t(CH_KEEP, 1, nullptr, nullptr, "Simple Test") {
        msg("[SimpleTest] Constructor called\n");
        
        // Add some test data
        items.push_back("Test Item 1");
        items.push_back("Test Item 2");
        items.push_back("Test Item 3");
        
        msg("[SimpleTest] Loaded %d items\n", (int)items.size());
    }
    
    virtual size_t idaapi get_count() const override {
        return items.size();
    }
    
    virtual void idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override {
        if (n < items.size()) {
            cols->clear();
            cols->push_back(items[n]);
        }
    }
};

// Test function
void test_simple_chooser() {
    msg("[SimpleTest] Creating simple chooser...\n");
    SimpleTestChooser* test = new SimpleTestChooser();
    
    msg("[SimpleTest] Calling choose()...\n");
    bool result = test->choose();
    msg("[SimpleTest] choose() returned: %s\n", result ? "true" : "false");
    
    if (!result) {
        msg("[SimpleTest] Failed to display simple chooser\n");
        delete test;
    } else {
        msg("[SimpleTest] Simple chooser displayed successfully\n");
    }
}