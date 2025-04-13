package edit

import (
	"github.com/please-build/buildtools/build"

	"github.com/please-build/puku/kinds"
	"github.com/please-build/puku/logging"
)

var log = logging.GetLogger()

type Rule struct {
	Dir  string
	Kind *kinds.Kind
	*build.Rule
}

// SetOrDeleteAttr will make sure the attribute with the given name matches the values passed in. It will keep the
// existing expressions in the list to maintain things like comments.
func (rule *Rule) SetOrDeleteAttr(name string, values []string) {
	if len(values) == 0 {
		rule.DelAttr(name)
		return
	}

	valuesMap := make(map[string]struct{})
	for _, v := range values {
		valuesMap[v] = struct{}{}
	}

	listExpr, _ := rule.Attr(name).(*build.ListExpr)
	if listExpr == nil {
		listExpr = &build.ListExpr{}
	}

	exprs := make([]build.Expr, 0, len(values))
	done := map[string]struct{}{}

	// Loop through the existing values, filtering out any that aren't supposed to be there
	for _, expr := range listExpr.List {
		val, ok := expr.(*build.StringExpr)
		if !ok {
			continue
		}
		if _, ok := valuesMap[val.Value]; ok {
			exprs = append(exprs, val)
			done[val.Value] = struct{}{}
		}
	}

	// Loops through the value adding any new values that didn't used to be there
	for _, v := range values {
		if _, done := done[v]; !done {
			exprs = append(exprs, NewStringExpr(v))
		}
	}

	listExpr.List = exprs
	rule.SetAttr(name, listExpr)
}

func (rule *Rule) IsTest() bool {
	return rule.Kind.Type == kinds.Test
}

func (rule *Rule) SrcsAttr() string {
	return rule.Kind.SrcsAttr
}

func (rule *Rule) AddSrc(src string) {
	srcsAttr := rule.SrcsAttr()

	// Get the existing attribute value
	existingAttr := rule.Attr(srcsAttr)
	if existingAttr == nil {
		// If there's no existing attribute, create a new list with just the new source
		srcs := rule.AttrStrings(srcsAttr)
		rule.SetOrDeleteAttr(srcsAttr, append(srcs, src))
		return
	}

	// Check if we have a list expression
	if listExpr, ok := existingAttr.(*build.ListExpr); ok {
		log.Debugf("ListExpr: %v", build.FormatString(listExpr))
		// If it's a list, we can just append to it using SetOrDeleteAttr
		srcs := rule.AttrStrings(srcsAttr)
		rule.SetOrDeleteAttr(srcsAttr, append(srcs, src))
		return
	}

	// Check if it's a call expression (e.g., glob([...]))
	if call, ok := existingAttr.(*build.CallExpr); ok {
		log.Debugf("CallExpr: %v", call)
		// Create a binary expression: glob([...]) + ["new_src"]
		newExpr := &build.BinaryExpr{
			X:         existingAttr,
			Y:         &build.ListExpr{List: []build.Expr{NewStringExpr(src)}},
			Op:        "+",
			LineBreak: true,
		}
		log.Debugf("NewExpr: %+v", build.FormatString(newExpr))
		rule.SetAttr(srcsAttr, newExpr)
		return
	}

	// Check if it's already a binary expression (e.g., glob([...]) + [...])
	if binExpr, ok := existingAttr.(*build.BinaryExpr); ok && binExpr.Op == "+" {
		log.Debugf("BinaryExpr: %v", build.FormatString(binExpr))
		// Find the rightmost operand of the binary expression chain
		rightmostExpr := binExpr
		for {
			if yBin, ok := rightmostExpr.Y.(*build.BinaryExpr); ok && yBin.Op == "+" {
				rightmostExpr = yBin
				continue
			}
			break
		}

		// Check if the rightmost part is a list we can append to
		if rightList, ok := rightmostExpr.Y.(*build.ListExpr); ok {
			// Add to the existing list
			rightList.List = append(rightList.List, NewStringExpr(src))
		} else {
			// Create a new list and append the original Y and our new item
			rightmostExpr.Y = &build.BinaryExpr{
				X:         rightmostExpr.Y,
				Y:         &build.ListExpr{List: []build.Expr{NewStringExpr(src)}},
				Op:        "+",
				LineBreak: true,
			}
		}
		rule.SetAttr(srcsAttr, binExpr)
		return
	}

	// Default fallback: replace with a list containing the retrieved strings plus the new src
	srcs := rule.AttrStrings(srcsAttr)
	rule.SetOrDeleteAttr(srcsAttr, append(srcs, src))
}

func (rule *Rule) RemoveSrc(rem string) {
	log.Debugf("RemoveSrc: %s", rem)
	// TODO(ryan): Debug why RemoveSrc is doing the wrong thing
	srcsAttr := rule.SrcsAttr()

	// Get existing attribute
	existingAttr := rule.Attr(srcsAttr)
	if existingAttr == nil {
		return
	}

	// Check if attribute is a list
	if listExpr, ok := existingAttr.(*build.ListExpr); ok {
		// Filter the list to remove the item
		filteredList := make([]build.Expr, 0, len(listExpr.List))
		for _, item := range listExpr.List {
			if stringExpr, ok := item.(*build.StringExpr); ok && stringExpr.Value == rem {
				// Skip this item
				continue
			}
			filteredList = append(filteredList, item)
		}

		// If the list is now empty, remove the attribute
		if len(filteredList) == 0 {
			rule.DelAttr(srcsAttr)
			return
		}

		// Otherwise update with the filtered list
		listExpr.List = filteredList
		rule.SetAttr(srcsAttr, listExpr)
		return
	}

	//	// For call expressions and binary expressions, we need to work with the string
	//	// representation and rebuild the structure
	//	srcs := rule.AttrStrings(srcsAttr)
	//
	//	// Filter out the source to be removed
	//	set := make([]string, 0, len(srcs))
	//	for _, src := range srcs {
	//		if src != rem {
	//			set = append(set, src)
	//		}
	//	}

	// If we're dealing with a binary expression or call expression where the right-hand side
	// contains just the removed source, we need to be careful
	if binExpr, ok := existingAttr.(*build.BinaryExpr); ok && binExpr.Op == "+" {
		// Check if there are any sources left after removing
		//		if len(set) == 0 {
		//			// Remove the entire attribute
		//			rule.DelAttr(srcsAttr)
		//			return
		//		}

		// Check if we have a simple glob + [item] expression
		if _, isCall := binExpr.X.(*build.CallExpr); isCall {
			// Preserve the glob call, and update the right side if needed
			rightList, isRightList := binExpr.Y.(*build.ListExpr)
			if isRightList && len(rightList.List) == 1 {
				if strExpr, isStr := rightList.List[0].(*build.StringExpr); isStr && strExpr.Value == rem {
					// If we're removing the only item on the right side, just revert to the glob call
					rule.SetAttr(srcsAttr, binExpr.X)
					return
				}
			}
		}

		//		// For more complex expressions, we'll rebuild based on the string list we extracted
		//		if len(set) == len(srcs) {
		//			// Nothing was removed, keep the expression as is
		//			return
		//		}
	}

	// Default fallback: update with the filtered list
	srcs := rule.AttrStrings(srcsAttr)

	// Filter out the source to be removed
	set := make([]string, 0, len(srcs))
	for _, src := range srcs {
		if src != rem {
			set = append(set, src)
		}
	}

	rule.SetOrDeleteAttr(srcsAttr, set)
}

func (rule *Rule) LocalLabel() string {
	return ":" + rule.Name()
}

func (rule *Rule) Label() string {
	return BuildTarget(rule.Name(), rule.Dir, "")
}

func NewRule(r *build.Rule, kindType *kinds.Kind, pkgDir string) *Rule {
	return &Rule{
		Dir:  pkgDir,
		Kind: kindType,
		Rule: r,
	}
}
