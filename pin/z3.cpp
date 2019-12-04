#include "z3++.h"
#include <iostream>

z3::context   *z3Context;
z3::expr      *z3Var;
z3::solver    *z3Solver;
z3::expr      *z3Equation;
z3::model     *z3Model;

int main(void)
{
	unsigned int goodValue;
	z3Context   = new z3::context;
    z3Var       = new z3::expr(z3Context->bv_const("x", 32));
    z3Solver    = new z3::solver(*z3Context);

    /* x ^ 0x33 == 0x77 */
    z3Equation  = new z3::expr(*z3Var);
    *z3Equation = (*z3Var ^ 0x33);
    *z3Equation = (*z3Equation == 0x77);

    z3Solver->add(*z3Equation);
    z3Solver->check();
    z3Model = new z3::model(z3Solver->get_model());
    std::cout << Z3_solver_to_string(*z3Context, *z3Solver) << std::endl;
    std::cout << Z3_model_to_string(*z3Context, *z3Model) << std::endl;

    Z3_get_numeral_uint(*z3Context, z3Model->get_const_interp((*z3Model)[0]), &goodValue); 
    std::cout << "The good value is 0x" << std::hex << goodValue << std::endl;

    delete z3Model;
    delete z3Equation;
    delete z3Var;
    delete z3Solver;
    delete z3Context;
	return 0;
}

/* g++ z3.cpp -lz3 -o z3 */