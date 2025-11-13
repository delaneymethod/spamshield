<?php

use PhpCsFixer\Runner\Parallel\ParallelConfigFactory;

$finder = (new PhpCsFixer\Finder())
    ->in([__DIR__.'/src', __DIR__.'/tests'])
    ->name('*.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);

return (new PhpCsFixer\Config())
    ->setParallelConfig(ParallelConfigFactory::detect())
    ->setRiskyAllowed(true)
    ->setFinder($finder)
    ->setCacheFile(__DIR__ . '/.php-cs-fixer.cache')
    ->setRules([
        '@PSR12' => true,
        '@Symfony' => true,
        '@Symfony:risky' => true,
        '@PHP80Migration' => true,
        '@PHP8x0Migration:risky' => true,
        '@PhpCsFixer' => true,
        'array_indentation' => true,
        'array_syntax' => ['syntax' => 'short'],
        'binary_operator_spaces' => [
            'default' => 'single_space',
            'operators' => [
                '='  => 'single_space',
                '=>' => 'single_space',
            ],
        ],
        'protected_to_private' => false,
        'combine_nested_dirname' => true,
        'linebreak_after_opening_tag' => true,
        'list_syntax' => ['syntax' => 'short'],
        'single_trait_insert_per_statement' => true,
        'ternary_to_null_coalescing' => true,
        'multiline_whitespace_before_semicolons' => ['strategy' => 'new_line_for_chained_calls'],
        'php_unit_internal_class' => false,
        'blank_line_before_statement' => ['statements' => ['return', 'try', 'if', 'for', 'foreach', 'while']],
        'combine_consecutive_unsets' => true,
        'declare_strict_types' => false, // flip to true if you enable strict_types
        'fully_qualified_strict_types' => true,
        'modernize_types_casting' => true,
        'native_function_invocation' => ['include' => ['@all']],
        'no_unused_imports' => true,
        'not_operator_with_successor_space' => true,
        'ordered_imports' => ['imports_order' => ['class', 'function', 'const']],
        'phpdoc_align' => ['align' => 'left'],
        'phpdoc_order' => true,
        'phpdoc_trim' => true,
        'single_quote' => true,
        'strict_param' => true,
        'trailing_comma_in_multiline' => ['elements' => ['arrays', 'arguments', 'parameters']],
        'yoda_style' => false,
    ])
    ->setRules([
        'header_comment' => [
            'header' => "SpamShield\n(c) 2025 Sean Delaney\nSPDX-License-Identifier: MIT\n\nThis file is part of the delaneymethod/spamshield package.\nSee the LICENSE file in the project root for license details.",
            'comment_type' => 'PHPDoc',
            'location' => 'after_open',
            'separate' => 'both',
        ],
    ]);
