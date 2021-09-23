#include <assert.h>
#include<math.h>
#include "common.h"
#include "point.h"

void
point_translate(struct point *p, double x, double y)
{
	p->x = x;
	p->y = y;
}

double
point_distance(const struct point *p1, const struct point *p2)
{
	return sqrt(pow(p1->x - p2->x, 2) + pow(p1->y - p2->y, 2));
}

int
point_compare(const struct point *p1, const struct point *p2)
{
	struct point zero;
	point_set(&zero, 0.0, 0.0);
	double p1_len = point_distance(p1, &zero);
	double p2_len = point_distance(p2, &zero);
	if(p1_len < p2_len) return -1;
	else if(p1_len == p2_len) return 0;
	else return 1;
}
