/* An Objective-C program for the Mach-O metadata tests: a root class of its own (no Foundation
   on the build machine), a subclass with ivars, a property, instance and class methods, a category. */
int printf(const char *, ...);
typedef struct objc_class *Class;
typedef struct objc_object { Class isa; } *id;
typedef struct objc_selector *SEL;
id objc_msgSend(id, SEL, ...);

__attribute__((objc_root_class))
@interface Base { Class isa; }
+ (id)alloc;
- (id)init;
@end

@interface Animal : Base { int legs; }
@property int age;
- (int)legs;
- (void)setLegs:(int)n;
- (void)speak:(const char *)word times:(int)n;
@end

@implementation Base
+ (id)alloc { return 0; }
- (id)init { return self; }
@end

@implementation Animal
- (int)legs { return legs; }
- (void)setLegs:(int)n { legs = n; }
- (void)speak:(const char *)word times:(int)n {
    for (int i = 0; i < n; i++) printf("%s %d\n", word, legs);
}
@end

int main(void) {
    Animal *a = [[Animal alloc] init];
    [a setLegs:4];
    a.age = 3;
    [a speak:"woof" times:a.age];
    return [a legs];
}

@interface Animal (Tricks)
- (int)roll:(int)n;
+ (id)make;
@end

@implementation Animal (Tricks)
- (int)roll:(int)n { return n * legs; }
+ (id)make { return [[Animal alloc] init]; }
@end
