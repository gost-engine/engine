package Utils;
use strict;
use warnings;

# # Implemented using ChatGPT
sub cartesian_product_iterator {
    my @arrays = @_;

    my $empty_result = sub {return};

    unless (@arrays) {
        return $empty_result;
    }

    for my $a (@arrays) {
        unless (@$a) {
            return $empty_result;
        }
    }

    my @idx = (0) x @arrays;
    my $done = 0;

    return sub {
        return if $done;
        my @current = map {$arrays[$_]->[$idx[$_]]} 0 .. $#arrays;

        # increment indices
        for (my $i = $#idx ; $i >= 0 ; $i--) {
            $idx[$i]++;
            if ($idx[$i] < @{$arrays[$i]}) {
                last;
            }
            else {
                $idx[$i] = 0;
                if ($i == 0) {$done = 1}
            }
        }
        return \@current;
    };
}

1;
