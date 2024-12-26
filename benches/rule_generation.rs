use criterion::{black_box, criterion_group, criterion_main, Criterion};
use yara_rule_generator::{
    patterns::{ENCRYPTION_APIS, RANSOMWARE_EXTENSIONS},
    ransomware_template, RuleBuilder,
};

fn benchmark_simple_rule(c: &mut Criterion) {
    c.bench_function("simple_rule", |b| {
        b.iter(|| {
            RuleBuilder::new(black_box("test_rule"))
                .with_string(black_box("$test"), black_box("test pattern"))
                .unwrap()
                .with_condition(black_box("$test"))
                .build()
                .unwrap()
                .to_string()
        })
    });
}

fn benchmark_complex_rule(c: &mut Criterion) {
    c.bench_function("complex_rule", |b| {
        b.iter(|| {
            let mut rule = ransomware_template(black_box("complex_rule"));

            // Add multiple patterns
            for (i, api) in ENCRYPTION_APIS.iter().enumerate() {
                rule = rule.with_string(&format!("$api_{}", i), api).unwrap();
            }

            for (i, ext) in RANSOMWARE_EXTENSIONS.iter().enumerate() {
                rule = rule.with_string(&format!("$ext_{}", i), ext).unwrap();
            }

            let rule = rule
                .with_condition("any of ($api_*) and any of ($ext_*)")
                .build()
                .unwrap();

            rule.to_string()
        })
    });
}

fn benchmark_rule_validation(c: &mut Criterion) {
    use yara_rule_generator::validation::{validate_rule, ValidationOptions};

    let rule = RuleBuilder::new("test_rule")
        .with_string("$test", "test pattern")
        .unwrap()
        .with_condition("$test")
        .build()
        .unwrap();

    let options = ValidationOptions {
        syntax_only: true,
        test_against_samples: false,
        max_file_size: 1024 * 1024,
        timeout: 10,
    };

    c.bench_function("rule_validation", |b| {
        b.iter(|| validate_rule(black_box(&rule.to_string()), black_box(&options)))
    });
}

criterion_group!(
    benches,
    benchmark_simple_rule,
    benchmark_complex_rule,
    benchmark_rule_validation
);
criterion_main!(benches);
