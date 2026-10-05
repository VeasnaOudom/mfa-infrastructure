import {
  MenuToggle,
  Select,
  SelectList,
  SelectOptionProps,
  SelectProps,
} from "@patternfly/react-core";
import { Children } from "react";

type TypeHeadSelectForMeProps = Omit<
  SelectProps,
  "name" | "toggle" | "selected" | "onClick" | "onSelect"
> & {
  toggleId?: string;
  className?: string;
  onClear?: () => void;
  isDisabled?: boolean;
  maxHeight?: string | number;
  width?: string | number;
  direction?: "up" | "down";
  placeholderText?: string;
  onSelect?: (value: string | number | object) => void;
  onToggle: (val: boolean) => void;
  selections?: string | string[] | number | number[];
  typeAheadAriaLabel?: string;
  chipGroupComponent?: React.ReactNode;
};

export const TypeaheadSelect = ({
                                  toggleId,
                                  onSelect,
                                  onToggle,
                                  placeholderText,
                                  maxHeight,
                                  width,
                                  direction,
                                  selections,
                                  typeAheadAriaLabel,
                                  chipGroupComponent,
                                  isDisabled,
                                  children,
                                  className,
                                  ...rest
                                }: TypeHeadSelectForMeProps) => {
  const childArray = Children.toArray(
    children,
  ) as React.ReactElement<SelectOptionProps>[];

  const propertyToString = (prop: string | number | undefined) =>
    typeof prop === "number" ? prop + "px" : prop;

  const toggle = () => {
    onToggle?.(!rest.isOpen);
  };

  const selectedValues = Array.isArray(selections)
    ? selections.map((selection) => String(selection))
    : typeof selections === "string" || typeof selections === "number"
      ? [String(selections)]
      : [];

  const selectedText = selectedValues
  .map((selection) =>
    childArray.find((child) => String(child.props.value) === selection),
  )
  .filter((child): child is React.ReactElement<SelectOptionProps> => !!child)
  .map((child) => {
    if (typeof child.props.children === "string") {
      return child.props.children;
    }

    if (typeof child.props.value === "string" || typeof child.props.value === "number") {
      return String(child.props.value);
    }

    return "";
  })
  .filter(Boolean)
  .join(", ");

  return (
    <Select
      {...rest}
      onClick={toggle}
      onOpenChange={(isOpen) => onToggle?.(isOpen)}
      onSelect={(_, value) => onSelect?.(value || "")}
      maxMenuHeight={propertyToString(maxHeight)}
      popperProps={{direction, width: propertyToString(width)}}
      toggle={(ref) => (
        <MenuToggle
          ref={ref}
          id={toggleId}
          variant="default"
          onClick={toggle}
          isDisabled={isDisabled}
          isExpanded={rest.isOpen}
          isFullWidth
          isFullHeight
          className={`edc-button-input ${className}`}
          aria-label={typeAheadAriaLabel}
        >
          {Array.isArray(selections) && selections.length > 0
            ? chipGroupComponent
            : selectedText || placeholderText}
        </MenuToggle>
      )}
    >
      <SelectList>{children}</SelectList>
    </Select>
  );
};