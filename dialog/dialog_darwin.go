package dialog

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

char* Prompt(char *prompt) {
    NSString *stringFromUTFString = [[NSString alloc] initWithUTF8String:prompt];

    [NSAutoreleasePool new];
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    [NSApp activateIgnoringOtherApps:YES];

    NSAlert *alert = [[[NSAlert alloc] init] autorelease];
    [alert setMessageText:stringFromUTFString];
    [alert addButtonWithTitle:@"Ok"];
    [alert addButtonWithTitle:@"Cancel"];
    [alert setAlertStyle:NSWarningAlertStyle];

    NSTextField *input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
    [alert setAccessoryView:input];

    if ([alert runModal] == NSAlertFirstButtonReturn) {
        [input validateEditing];
        return (char*)[[input stringValue] UTF8String];
    }

    return nil;
}
*/
import "C"
import "unsafe"

func Dialog(prompt string) (string, bool) {
	promptRef := C.CString(prompt)
	defer C.free(unsafe.Pointer(promptRef))
	val := C.Prompt(promptRef)
	if val == nil {
		return "", false
	}

	return C.GoString(val), true
}
