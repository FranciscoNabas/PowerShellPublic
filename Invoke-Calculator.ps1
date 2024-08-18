
<#
    .SYNOPSIS

        PowerShell calculator implementation.

    .DESCRIPTION
        
        This file contains two functions that implements a simple calculator.
        
        The first function implements the Shunting Yard algorithm that converts an expression to the
        Reverse Polish Notation and feeds it to a solver loop. This is a simpler version that accepts
        only single digit values and does not process white spaces.
    
        The second function implements a tokenizer using a Finite State Machine to convert the expression
        to a list of tokens that then get's feeded to the Shunting Yard algorithm, converted to the Reverse
        Polish Notation and then solved. This implementation defines a 'Compiler' object, which contains the
        tokenizer 'Parse' method. This could also be easily implemented using a functional approach.

        About unary operators:

            You can use the unary operators '+' and '-' to determine the number signing.
            On the simple version, more than 3 operators in a row is undetermined behavior.
            On the complete version more than 2 operators in a row throws an exception, and only '+' and '-' can follow an operator.

        About decimal points:

            Obviously only one decimal point is allowed per numeric literal token.
            If a numeric literal starts or ends with a decimal point a zero is appended.
            Ex.: .69 ~> 0.69 and 69. ~> 69.0.
    
        This code is not new, in fact it was implemented based on the Wikipedia definition of the Shunting
        Yard Algorithm, and the 'DIY Programming Language' video series from javidx9 (links on the bottom).
        You won't find a better explanation of the Shunting Yard Algorithm and a Finite State Machine!
    
        This code was NOT extensively tested and might contain bugs. Use at your own risk.
        The functions were designed to work with the '-Debug' parameter.

    .PARAMETER Expression

        The expression to be calculated. This expression accepts the operators: ^, /, *, +, -.
        You can also use parenthesis to enforce order of operations.
        For the simple version the expression must contain single digit integer numbers.
        The complete version accepts double numbers.

    .EXAMPLE

        Invoke-Calculator -Expression '6+(3-2)*5' # Simple version.

    .EXAMPLE

        Invoke-Calculator '10.432*2.34/(69.69-420)^2' # Complete version

    .NOTES

        Scripted by: Francisco Nabas
        Version: 1.0
        Version date: 2024-08-17
        https://github.com/francisconabas

    .LINK

        Shunting yard algorithm:
        https://en.wikipedia.org/wiki/Shunting_yard_algorithm

        DIY Programming Language #1: The Shunting Yard Algorithm:
        https://www.youtube.com/watch?v=unh6aK8WMwM&t=1683s

        DIY Programming Language #2: Tokenising with Finite State Machine:
        https://www.youtube.com/watch?v=wrj3iuRdA-M&t=1924s
#>


## SIMPLE VERSION ##
function Invoke-Calculator {

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            Position = 0,
            HelpMessage = "The expression to be calculated."
        )]
        [string]$Expression
    )

    # The token type.
    enum TokenType {
        LiteralNumeric
        Operator
        Unknown
        ParanthesisOpen
        ParenthesisClose
    }

    # Operator associativity.
    enum OperatorAssociativity {
        Right
        Left
    }

    # This class defines an operator.
    class Operator {
        [UInt32]$Precedence
        [UInt32]$Arguments
        [OperatorAssociativity]$Associativity
    }

    # This class defines a token.
    # The 'PossibleOperator' property is only defined for '[TokenType]::Operator'.
    class Token {
        [string]$Token
        [TokenType]$Type
        [Operator]$PossibleOperator
    }

    # A map containing the supported operators.
    $operatorMap = [System.Collections.Generic.Dictionary[char, Operator]]::new()
    [void]$operatorMap.Add('^', [Operator]@{ Precedence = 4; Arguments = 2; Associativity = [OperatorAssociativity]::Right })
    [void]$operatorMap.Add('/', [Operator]@{ Precedence = 3; Arguments = 2; Associativity = [OperatorAssociativity]::Left })
    [void]$operatorMap.Add('*', [Operator]@{ Precedence = 3; Arguments = 2; Associativity = [OperatorAssociativity]::Left })
    [void]$operatorMap.Add('+', [Operator]@{ Precedence = 2; Arguments = 2; Associativity = [OperatorAssociativity]::Left })
    [void]$operatorMap.Add('-', [Operator]@{ Precedence = 2; Arguments = 2; Associativity = [OperatorAssociativity]::Left })

    # These are the two stacks used for the Shunting Yard Algorithm.
    $operatorStack = [System.Collections.Generic.Stack[Token]]::new()
    $outputStack = [System.Collections.Generic.Stack[Token]]::new()

    # This first loop goes through all the characters in the expression and
    # converts them to the Reverse Polish Notation.
    foreach ($character in $Expression.ToCharArray()) {
        $foundOperator = $null
        
        # Checking if it's a digit.
        if ([char]::IsNumber($character)) {
            $outputStack.Push([Token]@{ Token = [string]::new($character); Type = [TokenType]::LiteralNumeric; PossibleOperator = $null })
            $previousToken = $outputStack.Peek()
        }

        # Checking if is a parenthesis.
        elseif ($character -eq '(') {
            $operatorStack.Push([Token]@{ Token = [string]::new($character); Type = [TokenType]::ParanthesisOpen; PossibleOperator = $null })
            $previousToken = $operatorStack.Peek()
        }
        elseif ($character -eq ')') {
            while ($operatorStack.Count -gt 0 -and $operatorStack.Peek().Type -ne [TokenType]::ParanthesisOpen) {
                $outputStack.Push($operatorStack.Pop())
            }
            if ($operatorStack.Count -eq 0) {
                throw 'Unexpected parenthesis.'
            }
            if ($operatorStack.Peek().Type -eq [TokenType]::ParanthesisOpen) {
                [void]$operatorStack.Pop()
            }
            $previousToken = [Token]@{ Token = [string]::new($character); Type = [TokenType]::ParenthesisClose; PossibleOperator = $null }
        }

        # Checking if it's an operator.
        elseif ($operatorMap.TryGetValue($character, [ref]$foundOperator)) {

            # Making a copy in case we need to change the operator properties without affecting our map.
            $newOperator = [Operator]@{ Precedence = $foundOperator.Precedence; Arguments = $foundOperator.Arguments; Associativity = $foundOperator.Associativity }

            # Checking if it's an unary operator.
            if ($character -eq '-' -or $character -eq '+') {
                if ($null -eq $previousToken -or ($previousToken.Type -ne [TokenType]::LiteralNumeric -and $previousToken.Type -ne [TokenType]::ParenthesisClose)) {
                    $newOperator.Arguments = 1
                    $newOperator.Precedence = 100
                }
            }

            while ($operatorStack.Count -gt 0 -and $operatorStack.Peek().Type -ne [TokenType]::ParanthesisOpen) {
                $topOperator = $operatorStack.Peek()
                if ($topOperator.Type -eq [TokenType]::Operator) {
                    if ($topOperator.PossibleOperator.Precedence -gt $newOperator.Precedence -or ($topOperator.PossibleOperator.Precedence -eq $newOperator.Precedence -and $newOperator.Associativity -eq [OperatorAssociativity]::Left)) {
                        $outputStack.Push($topOperator)
                        [void]$operatorStack.Pop()
                    }
                    else {
                        break
                    }
                }
            }

            $operatorStack.Push([Token]@{ Token = [string]::new($character); Type = [TokenType]::Operator; PossibleOperator = $newOperator })
            $previousToken = $operatorStack.Peek()
        }
        else {
            throw "Bad symbol in expression: $character."
        }
    }

    # Draining the operator stack.
    while ($operatorStack.Count -gt 0) {
        $outputStack.Push($operatorStack.Pop())
    }

    # Reverting the stack so we can iterate in the right order later.
    $reversedStack = [System.Collections.Generic.Stack[Token]]::new($outputStack.ToArray())

    # Debug.
    if ($PSBoundParameters['Debug'] -eq [switch]::Present) {
        $reversePolishNotation = [string]::Empty
        foreach ($token in $reversedStack) {
            $reversePolishNotation = [string]::Join('', ($reversePolishNotation, $token.Token))
        }

        Write-Debug "Expression:                $Expression"
        Write-Debug "Reverse polish notation:   $reversePolishNotation"
    }

    # This loop goes through the tokens and perform the calculations.
    $solveStack = [System.Collections.Generic.Stack[double]]::new()
    foreach ($token in $reversedStack) {
        switch ($token.Type) {
            'LiteralNumeric' {
                # Push number to the solving stack.
                $solveStack.Push([double]::Parse($token.Token))
            }
            'Operator' {
                # Removing operands from the solving stack according to the number of
                # arguments accepted by the operator.
                [System.Collections.Generic.List[double]]$operands = @()
                for ($i = 0; $i -lt $token.PossibleOperator.Arguments; $i++) {
                    if ($solveStack.Count -eq 0) {
                        throw 'Bad expression.'
                    }
                    [void]$operands.Add($solveStack.Pop())
                }

                # Performing calculations for the operator.
                if ($token.PossibleOperator.Arguments -eq 2) {
                    switch ($token.Token) {
                        '^' { $result = [math]::Pow($operands[1], $operands[0]) }
                        '/' { $result = $operands[1] / $operands[0] }
                        '*' { $result = $operands[1] * $operands[0] }
                        '+' { $result = $operands[1] + $operands[0] }
                        '-' { $result = $operands[1] - $operands[0] }
                    }
                }

                # Unary operators.
                if ($token.PossibleOperator.Arguments -eq 1) {
                    switch ($token.Token) {
                        '+' { $result = +$operands[0] }
                        '-' { $result = -$operands[0] }
                    }
                }

                # Pushing the current result to the solving stack.
                $solveStack.Push($result)
            }
        }
    }

    return $result
}


## COMPLETE VERSION ##
function Invoke-Calculator {

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            Position = 0,
            HelpMessage = "The expression to be calculated."
        )]
        [string]$Expression
    )

    # The token type.
    enum TokenType {
        NumericLiteral
        Operator
        ParanthesisOpen
        ParenthesisClose
        Unknown
    }

    # Operator associativity.
    enum OperatorAssociativity {
        Right
        Left
    }

    # The tokenizer state for the Finite State Machine.
    enum TokenizerState {
        NewToken
        NumericLiteral
        ParanthesisOpen
        ParenthesisClose
        Operator
        CompleteToken
    }

    # This class defines an operator.
    class Operator {
        [UInt32]$Precedence
        [UInt32]$Arguments
        [OperatorAssociativity]$Associativity
    }

    # This class defines a token.
    # The 'Value' property is only defined for '[TokenType]::NumericLiteral'.
    # The 'Operator' property is only defined for '[TokenType]::Operator'.
    class Token {
        [TokenType]$Type = [TokenType]::Unknown
        [string]$Text = [string]::Empty
        [double]$Value = 0.0
        [Operator]$Operator

        # Used for debug.
        [string] ToString() {
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.Append("[$($this.Type)")
            
            for ($i = 0; $i -lt 16 - $this.Type.ToString().Length; $i++) {
                [void]$sb.Append(' ')
            }
            $sb.Append("]: $($this.Text)")
            
            return $sb.ToString()
        }
    }

    # A simple Parser Exception. We came this far, why not?
    class ParserException : Exception {
        ParserException([string]$message) : base($message) { }
    }

    # This class defines the compiler.
    # It abstracts the Finite State Machine, which is implemented by the 'Parse' method.
    # It adds security for the operators map, which is defined using a Immutable Dictionary.
    class Compiler {

        # The operators map containing the supported operators.
        hidden [System.Collections.Immutable.ImmutableDictionary[string, Operator]]$_operatorMap

        Compiler() {
            # Defining the map in the constructor assures the map can't be changed by the API user.
            # Remember that 'hidden' properties are still public properties in PowerShell.
            $keyValuePairCollection = [System.Collections.Generic.KeyValuePair[string, Operator][]]::new(5)
            $keyValuePairCollection[0] = [System.Collections.Generic.KeyValuePair[string, Operator]]::new('^', [Operator]@{ Precedence = 4; Arguments = 2; Associativity = 'Right'})
            $keyValuePairCollection[1] = [System.Collections.Generic.KeyValuePair[string, Operator]]::new('/', [Operator]@{ Precedence = 3; Arguments = 2; Associativity = 'Left'})
            $keyValuePairCollection[2] = [System.Collections.Generic.KeyValuePair[string, Operator]]::new('*', [Operator]@{ Precedence = 3; Arguments = 2; Associativity = 'Left'})
            $keyValuePairCollection[3] = [System.Collections.Generic.KeyValuePair[string, Operator]]::new('+', [Operator]@{ Precedence = 2; Arguments = 2; Associativity = 'Left'})
            $keyValuePairCollection[4] = [System.Collections.Generic.KeyValuePair[string, Operator]]::new('-', [Operator]@{ Precedence = 2; Arguments = 2; Associativity = 'Left'})

            $this._operatorMap = [System.Collections.Immutable.ImmutableDictionary]::CreateRange($keyValuePairCollection)
        }

        <#
            The tokenizer implementation.
            Param inputText: The expression to be tokenized.
            Exceptions: ParserException; System.ArgumentException.
        #>
        [System.Collections.Generic.List[Token]] Parse([string]$inputText) {
            if ([string]::IsNullOrEmpty($inputText)) {
                throw [ArgumentException]::new("Input to 'Parse' cannot be null or empty")
            }

            # The output token list.
            $output = [System.Collections.Generic.List[Token]]::new()

            # Finite state machine implementation.

            # Setting the initial machine state.
            $currentState = [TokenizerState]::NewToken
            $nextState = [TokenizerState]::NewToken
            $currentTokenString = [System.Text.StringBuilder]::new()
            $currentToken = [Token]::new()
            $currentOperator = [Operator]::new()
            $operatorSequenceCount = 0
            $parenthesisBalanceChecker = 0
            $containsDecimalPoint = $false

            # This loop goes through each character in the expression and creates the tokens.
            # We are using a while loop because not all states of the machine consumes characters.
            # Note that we're using '-le' instead of '-lt' to allow the last token to be finalized.
            # The 'CompleteToken' state does not consume characters.
            # I bet there's a better way of doing this too.
            $charCount = 0
            :mainLoop while ($charCount -le $inputText.Length) {
                switch ($currentState) {
                    
                    # It's the start of a new token.
                    'NewToken' {

                        # Guarding the string from out of bound access.
                        if ($charCount -ge $inputText.Length) {
                            break mainLoop
                        }
                        
                        # Reset the FSM status.
                        $currentTokenString.Clear()
                        $operatorSequenceCount = 0
                        $containsDecimalPoint = $false

                        # First digit analysis.

                        # Check if it's white space.
                        if ([char]::IsWhiteSpace($inputText[$charCount])) {
                            # Consume it, do nothing.
                            $nextState = [TokenizerState]::NumericLiteral
                            $charCount++
                        }
                        
                        # Check if it's a numeric literal.
                        elseif ($this.IsRealNumericDigit($inputText[$charCount])) {
                            
                            # If this token starts with a decimal digit we append a zero to the start.
                            if ($inputText[$charCount] -eq '.') {
                                [void]$currentTokenString.Append('0')
                                $containsDecimalPoint = $true
                            }

                            [void]$currentTokenString.Append($inputText[$charCount])
                            $nextState = [TokenizerState]::NumericLiteral
                            $charCount++
                        }

                        # Check if it's an operator.
                        # Since this is a calculator, all our operators are one char in length.
                        elseif ($this._operatorMap.TryGetValue($inputText[$charCount], [ref]$currentOperator)) {
                            [void]$currentTokenString.Append($inputText[$charCount])
                            $nextState = [TokenizerState]::Operator
                            $charCount++
                            $operatorSequenceCount++
                        }

                        # Check for parenthesis.
                        elseif ($inputText[$charCount] -eq '(') {
                            $nextState = [TokenizerState]::ParanthesisOpen
                        }
                        elseif ($inputText[$charCount] -eq ')') {
                            $nextState = [TokenizerState]::ParenthesisClose
                        }

                        # On a calculator we don't accept symbols, or anything other than numbers, operators and parenthesis.
                        else {
                            throw [ParserException]::new("Invalid character '$($inputText[$charCount])'. At index: $charCount.")
                        }
                    }
                    'NumericLiteral' {
                        if ($charCount -ge $inputText.Length) {

                            # There are no more chars to consume, so we complete this token.
                            $tokenString = $currentTokenString.ToString()
                            if ($tokenString.EndsWith('.')) {

                                # If this numeric literal ends with a decimal point we append a zero at the end.
                                $tokenString = [string]::Join('', $tokenString, '0')
                            }

                            $nextState = [TokenizerState]::CompleteToken
                            $currentToken.Type = [TokenType]::NumericLiteral
                            $currentToken.Text = $tokenString
                            $currentToken.Value = [double]::Parse($tokenString)

                            break
                        }

                        # Check if it's a numeric literal.
                        if ($this.IsRealNumericDigit($inputText[$charCount])) {

                            # Checking if we have more than one decimal point.
                            if ($inputText[$charCount] -eq '.') {
                                if ($containsDecimalPoint) {
                                    throw [ParserException]::new("Only one decimal point is allowed in a numeric construction. At index: $charCount.")
                                }
                                else {
                                    $containsDecimalPoint = $true
                                }
                            }

                            [void]$currentTokenString.Append($inputText[$charCount])
                            $nextState = [TokenizerState]::NumericLiteral
                            $charCount++
                        }
                        else {
                            # Anything else indicates the end of this numeric literal.
                            # Move the machine to the 'CompleteToken' state, but don't consume the character yet.
                            $tokenString = $currentTokenString.ToString()
                            $nextState = [TokenizerState]::CompleteToken
                            $currentToken.Type = [TokenType]::NumericLiteral
                            $currentToken.Text = $tokenString
                            $currentToken.Value = [double]::Parse($tokenString)
                        }
                    }
                    'ParanthesisOpen' {
                        # For parenthesis we just complete the token.
                        $nextState = [TokenizerState]::CompleteToken
                        $currentToken.Type = [TokenType]::ParanthesisOpen
                        $currentToken.Text = $inputText[$charCount]
                        $charCount++

                        # This is used to confirm all parenthesis are balanced.
                        $parenthesisBalanceChecker++
                    }
                    'ParenthesisClose' {
                        # For parenthesis we just complete the token.
                        $nextState = [TokenizerState]::CompleteToken
                        $currentToken.Type = [TokenType]::ParenthesisClose
                        $currentToken.Text = $inputText[$charCount]
                        $charCount++

                        # This is used to confirm all parenthesis are balanced.
                        $parenthesisBalanceChecker--
                    }
                    'Operator' {
                        if ($charCount -ge $inputText.Length) {

                            # There are no more chars to consume, so we complete this token.
                            $nextState = [TokenizerState]::CompleteToken
                            $currentToken.Type = [TokenType]::Operator
                            $currentToken.Text = $currentTokenString.ToString()
                            $currentToken.Operator = [Operator]@{ Precedence = $currentOperator.Precedence; Arguments = $currentOperator.Arguments; Associativity = $currentOperator.Associativity }

                            break
                        }

                        # Check if it's an operator.
                        $additionalOperator = $null
                        if ($this._operatorMap.TryGetValue($inputText[$charCount], [ref]$additionalOperator)) {
                            
                            # We don't accept more than two operators in a row.
                            if ($operatorSequenceCount -ge 2) {
                                throw [ParserException]::new("Too many operators in a row. At index: $charCount.")
                            }

                            # If the previous token was an operator we only accept unary operators.
                            if ($inputText[$charCount] -ne '+' -or $inputText[$charCount] -ne '-') {
                                throw [ParserException]::new("Only unary operators can follow an operator. At index: $charCount.")
                            }

                            # Caching the previous operator.
                            # This is the only place were a token is added to the list outsite the 'CompleteToken' state.
                            # I know, there must be a better way of doing this.
                            [void]$output.Add([Token]@{
                                Type = [TokenType]::Operator
                                Text = $currentTokenString.ToString()
                                Value = 0.0
                                Operator = [Operator]@{ Precedence = $currentOperator.Precedence; Arguments = $currentOperator.Arguments; Associativity = $currentOperator.Associativity }
                            })

                            # Resetting the state for the current operator.
                            $currentTokenString.Clear()
                            [void]$currentTokenString.Append($inputText[$charCount])
                            $nextState = [TokenizerState]::Operator
                            $currentOperator.Precedence = $additionalOperator.Precedence
                            $currentOperator.Arguments = $additionalOperator.Arguments
                            $currentOperator.Associativity = $additionalOperator.Associativity 
                            $charCount++
                            $operatorSequenceCount++
                        }
                        else {
                            # End of the operator token.
                            $nextState = [TokenizerState]::CompleteToken
                            $currentToken.Type = [TokenType]::Operator
                            $currentToken.Text = $currentTokenString.ToString()
                            $currentToken.Operator = [Operator]@{ Precedence = $currentOperator.Precedence; Arguments = $currentOperator.Arguments; Associativity = $currentOperator.Associativity }
                        }
                    }
                    'CompleteToken' {
                        # Saves the composited token.
                        # In .NET the list saves the reference object, so we need to make an explicit copy here.
                        [void]$output.Add([Token]@{ Type = $currentToken.Type; Text = $currentToken.Text; Value = $currentToken.Value; Operator = $currentToken.Operator })
                        $nextState = [TokenizerState]::NewToken
                    }
                }

                # Setting the current machine state.
                $currentState = $nextState
            }

            # Checking if all the parenthesis are balanced, that is, for
            # each open parenthesis there's a close one.
            if ($parenthesisBalanceChecker -ne 0) {
                throw [ParserException]::new("Parenthesis are not balanced. Balance: $parenthesisBalanceChecker.")
            }

            return $output
        }

        # Helper function to determine if a character is a digit or a decimal point.
        hidden [bool] IsRealNumericDigit([char]$character) {
            return [char]::IsNumber($character) -or $character -eq '.'
        }
    }

    # Creating the compiler and parsing the expression.
    $compiler = [Compiler]::new()
    $tokenList = $compiler.Parse($Expression)

    # Debug. Writes the tokens.
    if ($PSBoundParameters['Debug'] -eq [switch]::Present) {
        Write-Debug 'Tokenizer output:'
        foreach ($token in $tokenList) {
            Write-Debug "    $token"
        }
    }

    # These are the two stacks used for the Shunting Yard Algorithm.
    $operatorStack = [System.Collections.Generic.Stack[Token]]::new()
    $outputStack = [System.Collections.Generic.Stack[Token]]::new()

    # This loop iterates through the token list and converts them
    # to the Reverse Polish Notation.
    foreach ($token in $tokenList) {
        switch ($token.Type) {
            'NumericLiteral' {
                $outputStack.Push($token)
                $previousToken = $token
            }
            'Operator' {
                # Making a copy in case we need to change the operator properties without affecting our map.
                $newOperator = [Operator]@{ Precedence = $token.Operator.Precedence; Arguments = $token.Operator.Arguments; Associativity = $token.Operator.Associativity }

                # Checking if it's an unary operator.
                if ($token.Text -eq '-' -or $token.Text -eq '+') {
                    if ($null -eq $previousToken -or ($previousToken.Type -ne [TokenType]::LiteralNumeric -and $previousToken.Type -ne [TokenType]::ParenthesisClose)) {
                        $newOperator.Arguments = 1
                        $newOperator.Precedence = 100
                    }
                }

                while ($operatorStack.Count -gt 0 -and $operatorStack.Peek().Type -ne [TokenType]::ParanthesisOpen) {
                    $topOperator = $operatorStack.Peek()
                    if ($topOperator.Type -eq [TokenType]::Operator) {
                        if ($topOperator.Operator.Precedence -gt $newOperator.Precedence -or ($topOperator.Operator.Precedence -eq $newOperator.Precedence -and $newOperator.Associativity -eq [OperatorAssociativity]::Left)) {
                            $outputStack.Push($topOperator)
                            [void]$operatorStack.Pop()
                        }
                        else {
                            break
                        }
                    }
                }

                $operatorStack.Push($token)
                $previousToken = $token
            }
            'ParanthesisOpen' {
                $operatorStack.Push($token)
                $previousToken = $token
            }
            'ParenthesisClose' {
                while ($operatorStack.Count -gt 0 -and $operatorStack.Peek().Type -ne [TokenType]::ParanthesisOpen) {
                    $outputStack.Push($operatorStack.Pop())
                }
                if ($operatorStack.Count -eq 0) {
                    throw [ParserException]::new('Unexpected parenthesis.')
                }
                if ($operatorStack.Peek().Type -eq [TokenType]::ParanthesisOpen) {
                    [void]$operatorStack.Pop()
                }
                $previousToken = $token
            }
            Default {
                throw [ParserException]::("Unknown token in expression: $token.")
            }
        }
    }

    # Draining the operator stack.
    while ($operatorStack.Count -gt 0) {
        $outputStack.Push($operatorStack.Pop())
    }

    # Reverting the stack so we can iterate in the right order later.
    $reversedStack = [System.Collections.Generic.Stack[Token]]::new($outputStack.ToArray())

    # Debug. Prints the RPN tokens separated by a '|'.
    if ($PSBoundParameters['Debug'] -eq [switch]::Present) {
        $reversePolishNotation = [string]::Empty
        foreach ($token in $reversedStack) {
            $reversePolishNotation = [string]::Join('|', ($reversePolishNotation, $token.Text))
        }

        Write-Debug "Reverse polish notation: $reversePolishNotation"
    }

    # This loop goes through the tokens and perform the calculations.
    $solveStack = [System.Collections.Generic.Stack[double]]::new()
    foreach ($token in $reversedStack) {
        switch ($token.Type) {
            'NumericLiteral' {
                # Push numeric literal to the solving stack.
                $solveStack.Push($token.Value)
            }
            'Operator' {
                # Removing operands from the solving stack according to the number of
                # arguments accepted by the operator.
                [System.Collections.Generic.List[double]]$operands = @()
                for ($i = 0; $i -lt $token.Operator.Arguments; $i++) {
                    if ($solveStack.Count -eq 0) {
                        throw [ParserException]::new('Bad expression.')
                    }
                    [void]$operands.Add($solveStack.Pop())
                }

                # Performing calculations for the operator.
                if ($token.Operator.Arguments -eq 2) {
                    switch ($token.Text) {
                        '^' { $result = [math]::Pow($operands[1], $operands[0]) }
                        '/' { $result = $operands[1] / $operands[0] }
                        '*' { $result = $operands[1] * $operands[0] }
                        '+' { $result = $operands[1] + $operands[0] }
                        '-' { $result = $operands[1] - $operands[0] }
                    }
                }

                # Unary operators.
                if ($token.Operator.Arguments -eq 1) {
                    switch ($token.Token) {
                        '+' { $result = +$operands[0] }
                        '-' { $result = -$operands[0] }
                    }
                }

                # Pushing the current result to the solving stack.
                $solveStack.Push($result)
            }
        }
    }

    return $result
}
