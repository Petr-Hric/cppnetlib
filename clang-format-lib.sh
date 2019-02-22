#!/ bin / bash

find./ -regextype egrep - regex "(.*.h)|(.*.cpp)" - exec clang - format - i {}
\;
